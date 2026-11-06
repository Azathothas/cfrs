//! T-075: a datagram socket of the `LD_PRELOAD` shim takes the same user
//! only, as its stream sockets and the switch do. The test runs as root:
//! a sender with another uid sends first, then a sender of the same user.
//! The server must get the datagram of the same user only.

use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};

use podnet::vnet::shim;

const SERVER: &str = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void){
  int s=socket(AF_INET,SOCK_DGRAM,0);
  struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(19998);
  inet_pton(AF_INET,"10.66.0.2",&a.sin_addr);
  if(bind(s,(struct sockaddr*)&a,sizeof a)<0){perror("bind");return 1;}
  printf("ready\n"); fflush(stdout);
  char buf[64]={0};
  struct sockaddr_in from; socklen_t fl=sizeof from;
  int n=recvfrom(s,buf,sizeof buf-1,0,(struct sockaddr*)&from,&fl);
  if(n<0){perror("recvfrom");return 2;}
  printf("got %s\n", buf); fflush(stdout);
  return 0;
}
"#;

const SENDER: &str = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(int argc, char **argv){
  int s=socket(AF_INET,SOCK_DGRAM,0);
  struct sockaddr_in peer; memset(&peer,0,sizeof peer);
  peer.sin_family=AF_INET; peer.sin_port=htons(19998);
  inet_pton(AF_INET,"10.66.0.2",&peer.sin_addr);
  if(sendto(s,argv[1],strlen(argv[1]),0,(struct sockaddr*)&peer,sizeof peer)<0){perror("sendto");return 1;}
  return 0;
}
"#;

fn build(dir: &std::path::Path, name: &str, source: &str) -> std::path::PathBuf {
    let src = dir.join(format!("{name}.c"));
    std::fs::write(&src, source).unwrap();
    let out = dir.join(name);
    let status = Command::new(shim::compiler().unwrap())
        .arg("-O2")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .status()
        .unwrap();
    assert!(status.success(), "compiling {name} failed");
    out
}

#[test]
fn shim_datagram_of_another_user_is_dropped() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: the test needs root, to send from another uid");
        return;
    }
    if shim::compiler().is_err() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    // The other user must read the shim and run the sender.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let shim = shim::build(dir.path()).unwrap();
    let server = build(dir.path(), "server", SERVER);
    let sender = build(dir.path(), "sender", SENDER);
    for f in std::fs::read_dir(dir.path()).unwrap() {
        let f = f.unwrap().path();
        let _ = std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755));
    }
    let _ = std::fs::set_permissions(&shim.path, std::fs::Permissions::from_mode(0o755));
    let mut child = Command::new(&server)
        .env("LD_PRELOAD", &shim.path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    assert_eq!(lines.next().unwrap().unwrap(), "ready");
    let send = |text: &str, uid: Option<u32>| {
        let mut cmd = Command::new(&sender);
        cmd.arg(text).env("LD_PRELOAD", &shim.path);
        if let Some(uid) = uid {
            cmd.uid(uid).gid(uid);
        }
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "{text}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    send("other", Some(65534));
    send("own", None);
    let got = lines.next().unwrap().unwrap();
    let status = child.wait().unwrap();
    let mut err = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut err).unwrap();
    assert!(status.success(), "{err}");
    assert_eq!(got, "got own", "{err}");
    assert!(err.contains("dropped a datagram of user 65534"), "{err}");
}
