//! The table of the sockets of the program under the seccomp backend
//! (T-064).
//!
//! The key of an entry is the inode number of the socket of the program
//! end (the link `/proc/PID/fd/N` is `socket:[INODE]`). A `fork`, a `dup`,
//! a `dup2`, a `dup3`, an `fcntl(F_DUPFD)` and a descriptor sent with
//! `SCM_RIGHTS` give the same socket, thus the same entry, with no call to
//! stop. Each process of the pod and each thread finds the entry of its
//! descriptor with one `readlink`.
//!
//! A `close` removes the entry only when no other descriptor of the pod
//! refers to the socket. Some descriptors close with no `close` call (the
//! exit of a process, `execve` with close-on-exec, `close_range`). A sweep
//! removes the entries of these sockets: it runs when the table doubles,
//! and before the table refuses a socket at [`MAX_TRACKED_FDS`].

use std::collections::HashSet;
use std::os::unix::ffi::OsStrExt;

use crate::prelude::*;

/// The key of an entry: the inode number of the socket of the program end.
/// 0 is not a key: the sockets file system gives no inode 0.
pub(crate) type Key = u64;

/// The table size of the first sweep.
const FIRST_SWEEP: usize = 64;

pub(crate) struct Table {
    socks: HashMap<Key, Sock>,
    /// The first process of the pod.
    root: i32,
    /// Each task that made a stopped call, with its thread group id.
    tasks: HashMap<u32, i32>,
    /// The table size at which the next sweep runs.
    sweep_at: usize,
}

impl std::ops::Deref for Table {
    type Target = HashMap<Key, Sock>;
    fn deref(&self) -> &Self::Target {
        &self.socks
    }
}

impl std::ops::DerefMut for Table {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socks
    }
}

impl Table {
    pub(crate) fn new(root: i32) -> Self {
        Table {
            socks: HashMap::new(),
            root,
            tasks: HashMap::new(),
            sweep_at: FIRST_SWEEP,
        }
    }

    /// The key of the descriptor `fd` of the task `pid` (0 when it is not a
    /// socket). Record the process of the task for the sweep.
    pub(crate) fn key_of(&mut self, pid: u32, fd: i32) -> Key {
        if !self.tasks.contains_key(&pid) {
            if self.tasks.len() >= 4 * MAX_TRACKED_FDS {
                self.tasks.retain(|tid, _| alive(*tid as i32));
            }
            self.tasks.insert(pid, tgid_of(pid));
        }
        socket_inode(pid as i32, fd)
    }

    /// Whether the table has room for one more entry. Sweep first when
    /// the sweep is due.
    pub(crate) fn has_room(&mut self) -> bool {
        if self.socks.len() >= self.sweep_at {
            self.sweep();
            self.sweep_at = (self.socks.len() * 2).clamp(FIRST_SWEEP, MAX_TRACKED_FDS);
        }
        self.socks.len() < MAX_TRACKED_FDS
    }

    /// Remove each entry whose socket no process of the pod holds.
    fn sweep(&mut self) {
        self.tasks.retain(|tid, _| alive(*tid as i32));
        let mut live = HashSet::new();
        let mut read = 0;
        for process in self.processes() {
            if let Some(sockets) = sockets_of(process) {
                read += 1;
                live.extend(sockets.into_iter().map(|(_, key)| key));
            }
        }
        // No table could be read: keep each entry.
        if read > 0 {
            self.socks.retain(|key, _| live.contains(key));
        }
    }

    /// The processes of the pod: the root and its descendants, and each
    /// process that made a stopped call (a process whose parent exited).
    fn processes(&self) -> HashSet<i32> {
        let mut found = HashSet::new();
        let mut todo: Vec<i32> = vec![self.root];
        todo.extend(self.tasks.values());
        while let Some(process) = todo.pop() {
            if process <= 0 || !found.insert(process) {
                continue;
            }
            let Ok(threads) = std::fs::read_dir(format!("/proc/{process}/task")) else {
                continue;
            };
            for thread in threads.flatten() {
                let path = thread.path().join("children");
                if let Ok(text) = std::fs::read_to_string(path) {
                    todo.extend(
                        text.split_whitespace()
                            .filter_map(|p| p.parse::<i32>().ok()),
                    );
                }
            }
        }
        found
    }

    /// Whether a descriptor of the pod other than `fd` of the task `pid`
    /// refers to the socket `key`.
    pub(crate) fn other_copy(&self, pid: u32, fd: i32, key: Key) -> bool {
        let own = sockets_of(pid as i32).unwrap_or_default();
        if own.iter().any(|&(n, k)| k == key && n != fd) {
            return true;
        }
        let caller = self.tasks.get(&pid).copied().unwrap_or(pid as i32);
        self.processes()
            .into_iter()
            .filter(|&process| process != caller)
            .any(|process| sockets_of(process).is_some_and(|s| s.iter().any(|&(_, k)| k == key)))
    }
}

/// `close` of the descriptor `fd` (the socket `key`) by the task `pid`:
/// drop the entry when this is the last descriptor of the socket in the
/// pod. The kernel then does the close.
pub(crate) fn handle_close(
    lfd: RawFd,
    id: u64,
    fd: i32,
    key: Key,
    pid: u32,
    map: &mut Table,
) -> Result<()> {
    if key != 0 && map.contains_key(&key) && !map.other_copy(pid, fd, key) {
        map.remove(&key);
    }
    notif_continue(lfd, id)
}

/// The inode number of the descriptor `fd` of the supervisor.
pub(crate) fn inode_of(fd: RawFd) -> Result<Key> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is a valid buffer for one `struct stat`.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(std::io::Error::last_os_error()).context("fstat");
    }
    Ok(st.st_ino as Key)
}

/// The inode of the socket at the descriptor `fd` of the task `pid`; 0 when
/// the descriptor is not a socket or cannot be read.
fn socket_inode(pid: i32, fd: i32) -> Key {
    match std::fs::read_link(format!("/proc/{pid}/fd/{fd}")) {
        Ok(link) => parse_socket_link(link.as_os_str().as_bytes()),
        Err(_) => 0,
    }
}

/// The inode of a link `socket:[INODE]`; 0 for another link.
fn parse_socket_link(link: &[u8]) -> Key {
    link.strip_prefix(b"socket:[")
        .and_then(|rest| rest.strip_suffix(b"]"))
        .and_then(|digits| std::str::from_utf8(digits).ok()?.parse().ok())
        .unwrap_or(0)
}

/// Each socket of the process `pid`: (descriptor, inode). `None` when its
/// table of descriptors cannot be read.
fn sockets_of(pid: i32) -> Option<Vec<(i32, Key)>> {
    let entries = std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Some(fd) = entry.file_name().to_str().and_then(|n| n.parse().ok()) else {
            continue;
        };
        if let Ok(link) = std::fs::read_link(entry.path()) {
            let key = parse_socket_link(link.as_os_str().as_bytes());
            if key != 0 {
                out.push((fd, key));
            }
        }
    }
    Some(out)
}

/// The thread group id of the task `tid` (`Tgid:` of its status).
fn tgid_of(tid: u32) -> i32 {
    std::fs::read_to_string(format!("/proc/{tid}/status"))
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|l| l.strip_prefix("Tgid:"))
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(tid as i32)
}

fn alive(pid: i32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_socket_link_gives_its_inode() {
        assert_eq!(parse_socket_link(b"socket:[123456]"), 123456);
        assert_eq!(parse_socket_link(b"pipe:[77]"), 0);
        assert_eq!(parse_socket_link(b"/dev/null"), 0);
        assert_eq!(parse_socket_link(b"socket:[x]"), 0);
    }

    #[test]
    fn a_copy_of_a_socket_has_the_inode_of_the_socket() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let copy = a.try_clone().unwrap();
        let me = std::process::id();
        let key = Table::new(me as i32).key_of(me, a.as_raw_fd());
        assert_ne!(key, 0);
        assert_eq!(key, inode_of(a.as_raw_fd()).unwrap());
        assert_eq!(socket_inode(me as i32, copy.as_raw_fd()), key);
    }
}
