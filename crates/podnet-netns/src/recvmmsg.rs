//! `recvmmsg` on a datagram socket of the program under the seccomp backend
//! (T-066).
//!
//! The kernel gives the `AF_UNIX` address of the socketpair as the source of
//! each message. Thus the supervisor does the call as a series of `recvmsg`
//! reads: for each `mmsghdr` it takes one datagram from the inbox of the
//! socket, and it writes the data, the real source and `msg_len` into the
//! memory of the program.
//!
//! The call waits for the first message only (as with `MSG_WAITFORONE`).
//! Then it takes each message that waits, and it stops at the first
//! `mmsghdr` with no message. The kernel also checks the timeout only after
//! a message, so a call with no message waits with no limit, as here.

use crate::inbox::{complete, read_target, wait_answer, Inbox, RecvTarget, UIO_MAXIOV};
use crate::prelude::*;

/// The size of one `struct mmsghdr` of this target (the program has the
/// same ABI).
const MMSGHDR_SIZE: u64 = std::mem::size_of::<libc::mmsghdr>() as u64;

/// The offset of `msg_len` in `struct mmsghdr`.
const MSG_LEN_OFFSET: u64 = std::mem::offset_of!(libc::mmsghdr, msg_len) as u64;

/// `recvmmsg(fd, msgvec, vlen, flags, timeout)` on a socket that has the
/// inbox `inbox`.
pub(crate) fn handle(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    pid: u32,
    inbox: Arc<Inbox>,
) -> Result<()> {
    let fd = a[0] as i32;
    let msgvec = a[1];
    let vlen = (a[2] as usize).min(UIO_MAXIOV);
    let flags = a[3] as i32;
    if vlen == 0 {
        return notif_respond(lfd, id, 0, 0);
    }
    // A peek gives the same message to each `mmsghdr`: take one.
    let count = if flags & libc::MSG_PEEK != 0 { 1 } else { vlen };
    let mut targets = Vec::with_capacity(count);
    for index in 0..count {
        let entry = msgvec + index as u64 * MMSGHDR_SIZE;
        match read_target(mem, true, [a[0], entry, a[3], 0, 0, 0]) {
            Ok((target, _)) => targets.push((entry, target)),
            Err(errno) if index == 0 => return notif_respond(lfd, id, -1, errno),
            Err(_) => break,
        }
    }
    match fill(mem, pid, &inbox, &targets, flags) {
        Ok(0) => {
            let nonblocking = flags & libc::MSG_DONTWAIT != 0
                || child_fd_flags(pid, fd).is_some_and(|f| f & libc::O_NONBLOCK != 0);
            if nonblocking {
                return notif_respond(lfd, id, -1, libc::EAGAIN);
            }
            // A blocking call waits in its own task: the other system calls
            // of the program go on.
            let reader = inbox.clone();
            let attempt = move |mem: RawFd| match fill(mem, pid, &reader, &targets, flags) {
                Ok(0) => Ok(None),
                Ok(n) => Ok(Some(n)),
                Err(errno) => Err(errno),
            };
            tokio::spawn(wait_answer(lfd, id, pid, inbox, attempt));
            Ok(())
        }
        Ok(n) => notif_respond(lfd, id, n, 0),
        Err(errno) => notif_respond(lfd, id, -1, errno),
    }
}

/// Take a message for each `mmsghdr` of `targets` while messages wait, and
/// write each one. Give the count of messages. An error after the first
/// message stops the call with the count; an error on the first message is
/// the errno of the call, as in the kernel.
fn fill(
    mem: RawFd,
    pid: u32,
    inbox: &Inbox,
    targets: &[(u64, RecvTarget)],
    flags: i32,
) -> std::result::Result<i64, i32> {
    let peek = flags & libc::MSG_PEEK != 0;
    let mut count = 0;
    for (entry, target) in targets {
        let written = match inbox.take(peek) {
            Ok(None) => break,
            Ok(Some((data, source))) => {
                let addr = inbox.address(source);
                complete(mem, pid, target, flags, &data, &addr).and_then(|len| {
                    let at = entry + MSG_LEN_OFFSET;
                    crate::seccomp::write_mem_to(mem, pid, at, &(len as u32).to_ne_bytes())
                        .map_err(|_| libc::EFAULT)
                })
            }
            Err(e) => Err(e.raw_os_error().unwrap_or(libc::EIO)),
        };
        match written {
            Ok(()) => count += 1,
            Err(errno) if count == 0 => return Err(errno),
            Err(_) => break,
        }
    }
    Ok(count)
}
