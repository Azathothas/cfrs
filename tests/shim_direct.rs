//! End-to-end tests for the `LD_PRELOAD` shim in direct mode.
//!
//! They compile the shim from its embedded source, compile two ordinary C
//! programs that use `AF_INET` sockets, and run them with the shim preloaded.
//! The kernel never sees an `AF_INET` bind or connect; the programs still
//! exchange data over `\0podnet-vnet/...` abstract names.
//!
//! If no C compiler is available the tests report that and pass, so they do
//! not fail on a host that cannot build the shim at all.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use podnet::vnet::shim;

fn have_compiler() -> bool {
    shim::compiler().is_ok()
}

/// Build the shim and a program into a scratch directory.
fn build_program(dir: &std::path::Path, name: &str, source: &str) -> std::path::PathBuf {
    let source_path = dir.join(format!("{name}.c"));
    std::fs::write(&source_path, source).unwrap();
    let output = dir.join(name);
    let cc = shim::compiler().unwrap();
    let status = Command::new(cc)
        .arg("-O2")
        .arg("-o")
        .arg(&output)
        .arg(&source_path)
        .status()
        .unwrap();
    assert!(status.success(), "compiling {name} failed");
    output
}

/// Run `server` until it prints `ready`, then `client`, then wait for the
/// server. Each step has a time limit of 30 s: a lost datagram or a missed
/// connection fails the test, and does not hang it.
fn run_pair(
    server: &mut Command,
    client: &mut Command,
) -> (std::process::Output, std::process::Output) {
    use std::io::{BufRead, Read};
    let limit = Duration::from_secs(30);
    let mut child = server
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut lines = Vec::new();
    loop {
        match rx.recv_timeout(limit) {
            Ok(line) if line == "ready" => break,
            Ok(line) => lines.push(line),
            Err(_) => {
                let _ = child.kill();
                panic!("the server did not print ready in 30 s: {lines:?}");
            }
        }
    }
    let wait = |child: &mut std::process::Child, what: &str| {
        let start = std::time::Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            if start.elapsed() > limit {
                let _ = child.kill();
                panic!("the {what} did not end in 30 s");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    let mut client_child = client
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let client_status = wait(&mut client_child, "client");
    let mut client_stdout = Vec::new();
    let mut client_stderr = Vec::new();
    client_child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut client_stdout)
        .unwrap();
    client_child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut client_stderr)
        .unwrap();
    let server_status = wait(&mut child, "server");
    reader.join().unwrap();
    lines.extend(rx.try_iter());
    let mut server_stderr = Vec::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut server_stderr)
        .unwrap();
    let mut server_stdout = lines.join("\n").into_bytes();
    server_stdout.push(b'\n');
    (
        std::process::Output {
            status: server_status,
            stdout: server_stdout,
            stderr: server_stderr,
        },
        std::process::Output {
            status: client_status,
            stdout: client_stdout,
            stderr: client_stderr,
        },
    )
}

#[test]
fn tcp_direct_mode_round_trip() {
    if !have_compiler() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let shim = shim::build(dir.path()).unwrap();
    assert!(shim.path.is_file());

    let server_src = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0);
  struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(18080);
  inet_pton(AF_INET,"10.66.0.2",&a.sin_addr);
  if(bind(s,(struct sockaddr*)&a,sizeof a)<0){perror("bind");return 1;}
  listen(s,4);
  struct sockaddr_in got; socklen_t gl=sizeof got;
  if(getsockname(s,(struct sockaddr*)&got,&gl)<0){perror("getsockname");return 2;}
  printf("server: bound %s:%d\n", inet_ntoa(got.sin_addr), ntohs(got.sin_port));
  printf("ready\n");
  fflush(stdout);
  int c=accept(s,0,0);
  char buf[256]={0}; int n=read(c,buf,sizeof buf-1);
  printf("server: read %dB: %s", n, buf);
  const char *r="HTTP/1.0 200 OK\r\n\r\nuserspace virtual net says hi\n";
  write(c,r,strlen(r)); close(c); close(s);
  return 0;
}
"#;
    let client_src = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0);
  struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(18080);
  inet_pton(AF_INET,"10.66.0.2",&a.sin_addr);
  if(connect(s,(struct sockaddr*)&a,sizeof a)<0){perror("connect");return 1;}
  struct sockaddr_in peer; socklen_t pl=sizeof peer;
  if(getpeername(s,(struct sockaddr*)&peer,&pl)<0){perror("getpeername");return 2;}
  printf("client: connected to %s:%d\n", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
  const char *q="GET /hello HTTP/1.0\r\n\r\n";
  write(s,q,strlen(q));
  char buf[512]={0}; int n=read(s,buf,sizeof buf-1);
  printf("client: got %dB\n", n);
  close(s); return 0;
}
"#;
    let server = build_program(dir.path(), "server", server_src);
    let client = build_program(dir.path(), "client", client_src);

    let mut server_cmd = Command::new(&server);
    server_cmd
        .env("LD_PRELOAD", &shim.path)
        .env("PODNET_VNET_LOG", "1");
    let mut client_cmd = Command::new(&client);
    client_cmd
        .env("LD_PRELOAD", &shim.path)
        .env("PODNET_VNET_LOG", "1");
    let (server_output, output) = run_pair(&mut server_cmd, &mut client_cmd);

    assert!(
        server_output.status.success(),
        "server failed: {}",
        String::from_utf8_lossy(&server_output.stderr)
    );
    assert!(
        output.status.success(),
        "client failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let server_stdout = String::from_utf8_lossy(&server_output.stdout);
    let client_stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        server_stdout.contains("server: bound 10.66.0.2:18080"),
        "{server_stdout}"
    );
    assert!(server_stdout.contains("read 23B"), "{server_stdout}");
    assert!(
        client_stdout.contains("connected to 10.66.0.2:18080"),
        "{client_stdout}"
    );
    assert!(client_stdout.contains("got 49B"), "{client_stdout}");
    // The kernel only ever saw the abstract name.
    let server_stderr = String::from_utf8_lossy(&server_output.stderr);
    let client_stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        server_stderr.contains("bind -> podnet-vnet/4/10.66.0.2/18080"),
        "{server_stderr}"
    );
    assert!(
        client_stderr.contains("connect -> podnet-vnet/4/10.66.0.2/18080"),
        "{client_stderr}"
    );
}

#[test]
fn udp_direct_mode_round_trip() {
    if !have_compiler() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let shim = shim::build(dir.path()).unwrap();

    let server_src = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void){
  int s=socket(AF_INET,SOCK_DGRAM,0);
  struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(19999);
  inet_pton(AF_INET,"10.66.0.2",&a.sin_addr);
  if(bind(s,(struct sockaddr*)&a,sizeof a)<0){perror("bind");return 1;}
  printf("ready\n"); fflush(stdout);
  char buf[256]={0};
  struct sockaddr_in from; socklen_t fl=sizeof from;
  int n=recvfrom(s,buf,sizeof buf-1,0,(struct sockaddr*)&from,&fl);
  if(n<0){perror("recvfrom");return 2;}
  printf("server: got %dB: %s\n", n, buf);
  const char *r="pong";
  sendto(s,r,strlen(r),0,(struct sockaddr*)&from,fl);
  close(s);
  return 0;
}
"#;
    let client_src = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void){
  int s=socket(AF_INET,SOCK_DGRAM,0);
  struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(20000);
  inet_pton(AF_INET,"10.66.0.2",&a.sin_addr);
  if(bind(s,(struct sockaddr*)&a,sizeof a)<0){perror("bind");return 1;}
  struct sockaddr_in peer; memset(&peer,0,sizeof peer);
  peer.sin_family=AF_INET; peer.sin_port=htons(19999);
  inet_pton(AF_INET,"10.66.0.2",&peer.sin_addr);
  const char *q="ping";
  if(sendto(s,q,strlen(q),0,(struct sockaddr*)&peer,sizeof peer)<0){perror("sendto");return 1;}
  char buf[64]={0};
  int n=recvfrom(s,buf,sizeof buf-1,0,0,0);
  printf("client: got %dB: %s\n", n, buf);
  close(s);
  return 0;
}
"#;
    let server = build_program(dir.path(), "userver", server_src);
    let client = build_program(dir.path(), "uclient", client_src);

    let mut server_cmd = Command::new(&server);
    server_cmd.env("LD_PRELOAD", &shim.path);
    let mut client_cmd = Command::new(&client);
    client_cmd.env("LD_PRELOAD", &shim.path);
    let (server_output, output) = run_pair(&mut server_cmd, &mut client_cmd);

    assert!(
        server_output.status.success(),
        "udp server failed: {}",
        String::from_utf8_lossy(&server_output.stderr)
    );
    assert!(
        output.status.success(),
        "udp client failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&server_output.stdout).contains("got 4B: ping"));
    assert!(String::from_utf8_lossy(&output.stdout).contains("got 4B: pong"));
}

/// A tiny guard that the test's own writer never blocks: stdout is piped and
/// small. This exists only to use `std::io::Write` so the import is not dead.
#[test]
fn piped_output_is_small() {
    let mut sink = Vec::new();
    sink.write_all(b"podnet-vnet").unwrap();
    assert_eq!(sink, b"podnet-vnet");
}

/// `PODNET_VNET_MAP_LOOPBACK` must encode `::1` as the same RFC 5952 literal the
/// Rust side would produce for the v4-mapped local address.
#[test]
fn ipv6_loopback_mapping_matches_the_rust_encoder() {
    if !have_compiler() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let shim = shim::build(dir.path()).unwrap();

    let server_src = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void){
  int s=socket(AF_INET6,SOCK_STREAM,0);
  struct sockaddr_in6 a; memset(&a,0,sizeof a);
  a.sin6_family=AF_INET6; a.sin6_port=htons(18081);
  inet_pton(AF_INET6,"::1",&a.sin6_addr);
  if(bind(s,(struct sockaddr*)&a,sizeof a)<0){perror("bind");return 1;}
  listen(s,4);
  printf("ready\n"); fflush(stdout);
  int c=accept(s,0,0);
  if(c<0){perror("accept");return 2;}
  char buf[16]={0}; int n=read(c,buf,sizeof buf);
  write(c,buf,n); close(c); close(s); return 0;
}
"#;
    let client_src = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void){
  int s=socket(AF_INET6,SOCK_STREAM,0);
  struct sockaddr_in6 a; memset(&a,0,sizeof a);
  a.sin6_family=AF_INET6; a.sin6_port=htons(18081);
  inet_pton(AF_INET6,"::1",&a.sin6_addr);
  if(connect(s,(struct sockaddr*)&a,sizeof a)<0){perror("connect");return 1;}
  const char *q="v6 mapped"; write(s,q,strlen(q));
  char buf[32]={0}; int n=read(s,buf,sizeof buf);
  printf("client: got %dB: %s\n", n, buf);
  close(s); return 0;
}
"#;
    let server = build_program(dir.path(), "v6server", server_src);
    let client = build_program(dir.path(), "v6client", client_src);

    let mut server_cmd = Command::new(&server);
    server_cmd
        .env("LD_PRELOAD", &shim.path)
        .env("PODNET_VNET_MAP_LOOPBACK", "1");
    let mut client_cmd = Command::new(&client);
    client_cmd
        .env("LD_PRELOAD", &shim.path)
        .env("PODNET_VNET_MAP_LOOPBACK", "1")
        .env("PODNET_VNET_LOG", "1");
    let (server_output, output) = run_pair(&mut server_cmd, &mut client_cmd);

    assert!(
        output.status.success(),
        "v6 client failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(server_output.status.success(), "v6 server failed");
    assert!(String::from_utf8_lossy(&output.stdout).contains("got 9B: v6 mapped"));
    // ::1 maps to ::ffff:10.66.0.2, which RFC 5952 renders ::ffff:a42:2.
    let client_stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        client_stderr.contains("podnet-vnet/6/::ffff:a42:2/18081"),
        "unexpected abstract name: {client_stderr}"
    );
}

/// accept and accept4 under the shim, with each kind of address buffer
/// (issue 41): a 16-byte sockaddr_in (and the byte after it is not
/// written), a 128-byte buffer, NULL, and accept4 with SOCK_CLOEXEC. Each
/// accept gives a peer of AF_INET with the length of a sockaddr_in, never
/// a length of 0 (Perl reads an empty peer as a failure). Then 1000 more
/// connections.
#[test]
fn accept_gives_a_peer_for_each_buffer() {
    if !have_compiler() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let shim = shim::build(dir.path()).unwrap();
    let server_src = r#"
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
static void answer(int c){ if(write(c,"hi\n",3)<0){} close(c); }
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0);
  struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(18082);
  inet_pton(AF_INET,"10.66.0.2",&a.sin_addr);
  if(bind(s,(struct sockaddr*)&a,sizeof a)<0){perror("bind");return 1;}
  if(listen(s,64)<0){perror("listen");return 1;}
  printf("ready\n"); fflush(stdout);
  struct { struct sockaddr_in in; unsigned char canary; } small;
  small.canary=0xa5; socklen_t l=sizeof small.in;
  int c=accept(s,(struct sockaddr*)&small.in,&l); if(c<0){perror("accept16");return 2;}
  printf("16: len=%u family=%d canary=%x\n",(unsigned)l,small.in.sin_family,small.canary); answer(c);
  struct sockaddr_storage big; socklen_t bl=128;
  c=accept(s,(struct sockaddr*)&big,&bl); if(c<0){perror("accept128");return 3;}
  printf("128: len=%u family=%d\n",(unsigned)bl,big.ss_family); answer(c);
  c=accept(s,NULL,NULL); if(c<0){perror("acceptnull");return 4;}
  printf("null: ok\n"); answer(c);
  struct sockaddr_in four; socklen_t fl=sizeof four;
  c=accept4(s,(struct sockaddr*)&four,&fl,SOCK_CLOEXEC); if(c<0){perror("accept4");return 5;}
  printf("accept4: len=%u family=%d cloexec=%d\n",(unsigned)fl,four.sin_family,(fcntl(c,F_GETFD)&FD_CLOEXEC)?1:0); answer(c);
  int zero=0;
  for(int i=0;i<1000;i++){ struct sockaddr_in p; socklen_t pl=sizeof p;
    c=accept(s,(struct sockaddr*)&p,&pl); if(c<0){perror("accept loop");return 6;}
    if(pl==0) zero++; answer(c); }
  printf("loop: 1000 zero=%d\n",zero);
  return 0;
}
"#;
    let client_src = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void){
  int ok=0;
  for(int i=0;i<1004;i++){
    int s=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family=AF_INET; a.sin_port=htons(18082);
    inet_pton(AF_INET,"10.66.0.2",&a.sin_addr);
    if(connect(s,(struct sockaddr*)&a,sizeof a)<0){perror("connect");return 1;}
    char buf[8]={0}; if(read(s,buf,sizeof buf)==3 && !memcmp(buf,"hi\n",3)) ok++;
    close(s);
  }
  printf("client: %d ok\n",ok);
  return 0;
}
"#;
    let server = build_program(dir.path(), "accept_server", server_src);
    let client = build_program(dir.path(), "accept_client", client_src);
    let mut server_cmd = Command::new(&server);
    server_cmd.env("LD_PRELOAD", &shim.path);
    let mut client_cmd = Command::new(&client);
    client_cmd.env("LD_PRELOAD", &shim.path);
    let (server_out, client_out) = run_pair(&mut server_cmd, &mut client_cmd);
    let s = String::from_utf8_lossy(&server_out.stdout);
    let c = String::from_utf8_lossy(&client_out.stdout);
    assert!(
        server_out.status.success(),
        "{s}{}",
        String::from_utf8_lossy(&server_out.stderr)
    );
    assert!(s.contains("16: len=16 family=2 canary=a5"), "{s}");
    assert!(s.contains("128: len=16 family=2"), "{s}");
    assert!(s.contains("null: ok"), "{s}");
    assert!(s.contains("accept4: len=16 family=2 cloexec=1"), "{s}");
    assert!(s.contains("loop: 1000 zero=0"), "{s}");
    assert!(c.contains("client: 1004 ok"), "{c}");
}

/// The Perl accept loop of issue 41: IO::Socket::INET under the shim
/// serves 10 connections. Before, accept gave a peer of length 0, and
/// Perl ended the loop at the first connection. Skipped with no perl.
#[test]
fn a_perl_accept_loop_serves_each_connection() {
    if !have_compiler() || Command::new("perl").arg("-e1").status().is_err() {
        eprintln!("skipping: no C compiler or no perl");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let shim = shim::build(dir.path()).unwrap();
    let server = r#"use IO::Socket::INET; $|=1;
my $s = IO::Socket::INET->new(LocalAddr=>"10.66.0.2", LocalPort=>18083, Listen=>8, ReuseAddr=>1) or die "listen: $!";
print "ready\n"; my $n = 0;
while (my $c = $s->accept) { print $c "hello\n"; close $c; $n++; last if $n == 10 }
print "served $n\n";"#;
    let client = r#"use IO::Socket::INET; my $ok = 0;
for (1..10) { my $c = IO::Socket::INET->new(PeerAddr=>"10.66.0.2", PeerPort=>18083) or die "connect: $!";
  my $l = <$c>; $ok++ if defined $l && $l eq "hello\n"; }
print "client $ok\n";"#;
    let mut server_cmd = Command::new("perl");
    server_cmd
        .arg("-e")
        .arg(server)
        .env("LD_PRELOAD", &shim.path);
    let mut client_cmd = Command::new("perl");
    client_cmd
        .arg("-e")
        .arg(client)
        .env("LD_PRELOAD", &shim.path);
    let (server_out, client_out) = run_pair(&mut server_cmd, &mut client_cmd);
    let s = String::from_utf8_lossy(&server_out.stdout);
    let c = String::from_utf8_lossy(&client_out.stdout);
    assert!(
        s.contains("served 10"),
        "{s}{}",
        String::from_utf8_lossy(&server_out.stderr)
    );
    assert!(
        c.contains("client 10"),
        "{c}{}",
        String::from_utf8_lossy(&client_out.stderr)
    );
}

/// Issue 64: two virtual binds to port 0 each get a free port (before, port
/// 0 was a name of its own and the second bind got EADDRINUSE); and a
/// client that binds 10.66.0.5:5555 is the peer that accept reports, also
/// through a 16-byte sockaddr_in (before, the kernel cut the abstract name
/// in that buffer, and the peer was 0.0.0.0:0).
#[test]
fn port_zero_and_the_peer_of_a_bound_client() {
    if !have_compiler() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let shim = shim::build(dir.path()).unwrap();
    let server_src = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
static int bound(int port){
  int s=socket(AF_INET,SOCK_STREAM,0);
  struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET;
  a.sin_port=htons(port); inet_pton(AF_INET,"10.66.0.2",&a.sin_addr);
  if(bind(s,(struct sockaddr*)&a,sizeof a)<0){perror("bind");return -1;}
  return s;
}
static int port_of(int s){ struct sockaddr_in a; socklen_t l=sizeof a;
  getsockname(s,(struct sockaddr*)&a,&l); return ntohs(a.sin_port); }
int main(void){
  int z1=bound(0), z2=bound(0); if(z1<0||z2<0) return 1;
  int p1=port_of(z1), p2=port_of(z2);
  printf("zero %d %d %s\n", p1, p2, (p1>=49152 && p2>=49152 && p1!=p2) ? "distinct" : "SAME");
  int s=bound(18085); if(s<0) return 2; listen(s,4);
  printf("ready\n"); fflush(stdout);
  struct sockaddr_in peer; socklen_t pl=sizeof peer;
  int c=accept(s,(struct sockaddr*)&peer,&pl); if(c<0){perror("accept");return 3;}
  char ip[32]; inet_ntop(AF_INET,&peer.sin_addr,ip,sizeof ip);
  printf("peer %s:%d len=%u\n", ip, ntohs(peer.sin_port), (unsigned)pl);
  if(write(c,"ok",2)<0){} close(c); return 0;
}
"#;
    let client_src = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0);
  struct sockaddr_in me; memset(&me,0,sizeof me); me.sin_family=AF_INET;
  me.sin_port=htons(5555); inet_pton(AF_INET,"10.66.0.5",&me.sin_addr);
  if(bind(s,(struct sockaddr*)&me,sizeof me)<0){perror("bind");return 1;}
  struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET;
  a.sin_port=htons(18085); inet_pton(AF_INET,"10.66.0.2",&a.sin_addr);
  if(connect(s,(struct sockaddr*)&a,sizeof a)<0){perror("connect");return 2;}
  char b[4]={0}; if(read(s,b,2)<0){} printf("client got %s\n", b); return 0;
}
"#;
    let server = build_program(dir.path(), "zero_server", server_src);
    let client = build_program(dir.path(), "zero_client", client_src);
    let mut server_cmd = Command::new(&server);
    server_cmd.env("LD_PRELOAD", &shim.path);
    let mut client_cmd = Command::new(&client);
    client_cmd.env("LD_PRELOAD", &shim.path);
    let (server_out, client_out) = run_pair(&mut server_cmd, &mut client_cmd);
    let s = String::from_utf8_lossy(&server_out.stdout);
    assert!(
        server_out.status.success(),
        "{s}{}",
        String::from_utf8_lossy(&server_out.stderr)
    );
    assert!(s.contains("distinct"), "{s}");
    assert!(s.contains("peer 10.66.0.5:5555 len=16"), "{s}");
    assert!(String::from_utf8_lossy(&client_out.stdout).contains("client got ok"));
}

/// Issue 64: a second build into the same directory does not run cc again.
#[test]
fn a_second_build_is_cached() {
    if !have_compiler() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let first = shim::build(dir.path()).unwrap();
    assert!(matches!(first.origin, shim::ShimOrigin::Compiled));
    let modified = std::fs::metadata(&first.path).unwrap().modified().unwrap();
    let second = shim::build(dir.path()).unwrap();
    assert!(matches!(second.origin, shim::ShimOrigin::Cached));
    assert_eq!(
        std::fs::metadata(&second.path).unwrap().modified().unwrap(),
        modified
    );
}

/// Issue 181: with no C compiler, `net shim --out DIR` uses the library
/// that a compiler made in DIR from the same source.
#[test]
fn a_built_shim_needs_no_compiler_later() {
    if !have_compiler() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let first = shim::build(dir.path()).unwrap();
    assert!(matches!(first.origin, shim::ShimOrigin::Compiled));
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_podnet"))
        .args(["net", "shim", "--out"])
        .arg(dir.path())
        .env("PATH", "/nonexistent")
        .env_remove("CC")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Issue 193: a client that did not bind gets a local address at connect
/// (10.66.0.2 and an ephemeral port), and the server sees it as the peer.
/// Before, getsockname gave 0.0.0.0:0, and so did the peer of accept.
#[test]
fn a_connected_client_has_a_local_address_and_the_server_sees_it() {
    if !have_compiler() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let shim = shim::build(dir.path()).unwrap();
    let server_src = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0);
  struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET;
  a.sin_port=htons(18086); inet_pton(AF_INET,"10.66.0.2",&a.sin_addr);
  if(bind(s,(struct sockaddr*)&a,sizeof a)<0){perror("bind");return 1;}
  listen(s,4); printf("ready\n"); fflush(stdout);
  struct sockaddr_in peer; socklen_t pl=sizeof peer;
  int c=accept(s,(struct sockaddr*)&peer,&pl); if(c<0){perror("accept");return 3;}
  char ip[32]; inet_ntop(AF_INET,&peer.sin_addr,ip,sizeof ip);
  printf("peer %s:%d\n", ip, ntohs(peer.sin_port)); fflush(stdout);
  char b[32]={0}; if(read(c,b,sizeof b-1)<0){} printf("client said %s\n", b);
  close(c); return 0;
}
"#;
    let client_src = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0);
  struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET;
  a.sin_port=htons(18086); inet_pton(AF_INET,"10.66.0.2",&a.sin_addr);
  if(connect(s,(struct sockaddr*)&a,sizeof a)<0){perror("connect");return 2;}
  struct sockaddr_in me; socklen_t l=sizeof me;
  getsockname(s,(struct sockaddr*)&me,&l);
  char ip[32]; inet_ntop(AF_INET,&me.sin_addr,ip,sizeof ip);
  char line[64]; snprintf(line,sizeof line,"%s:%d",ip,ntohs(me.sin_port));
  printf("local %s\n", line);
  if(write(s,line,strlen(line))<0){} return 0;
}
"#;
    let server = build_program(dir.path(), "auto_server", server_src);
    let client = build_program(dir.path(), "auto_client", client_src);
    let mut server_cmd = Command::new(&server);
    server_cmd.env("LD_PRELOAD", &shim.path);
    let mut client_cmd = Command::new(&client);
    client_cmd.env("LD_PRELOAD", &shim.path);
    let (server_out, client_out) = run_pair(&mut server_cmd, &mut client_cmd);
    let s = String::from_utf8_lossy(&server_out.stdout);
    let c = String::from_utf8_lossy(&client_out.stdout);
    assert!(server_out.status.success(), "{s}");
    let local = c
        .lines()
        .find_map(|l| l.strip_prefix("local "))
        .unwrap_or_else(|| panic!("{c}"));
    assert!(local.starts_with("10.66.0.2:"), "{local}");
    let port: u16 = local.rsplit(':').next().unwrap().parse().unwrap();
    assert!(port >= 49152, "{local}");
    assert!(s.contains(&format!("peer {local}")), "{s} / {c}");
    assert!(s.contains(&format!("client said {local}")), "{s}");
}

/// Issue 308: a stream socket of the shim takes the same user only. A shim
/// program of another user does not connect to a listener of root at its
/// abstract name, and does not accept a client of root. Root only (the test
/// runs the programs as uid 65534).
#[test]
fn the_shim_takes_the_same_user_only() {
    use std::io::{BufRead, Write as _};
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    // SAFETY: geteuid() has no precondition.
    if !have_compiler() || unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: no C compiler, or not root");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let shim = shim::build(dir.path()).unwrap();
    let port = 20000 + (std::process::id() % 20000) as u16;
    let program = |name: &str, body: &str| {
        let source = format!(
            r#"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(int argc,char**argv){{
  alarm(10);
  struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(atoi(argv[1]));
  inet_pton(AF_INET,"10.66.0.2",&a.sin_addr);
  int s=socket(AF_INET,SOCK_STREAM,0);
  {body}
}}
"#
        );
        let path = build_program(dir.path(), name, &format!("#include <stdlib.h>\n{source}"));
        let mut cmd = Command::new(path);
        cmd.env("LD_PRELOAD", &shim.path).uid(65534).gid(65534);
        cmd
    };
    let abstract_name = |port: u16| {
        std::os::unix::net::SocketAddr::from_abstract_name(
            format!("podnet-vnet/4/10.66.0.2/{port}").as_bytes(),
        )
        .unwrap()
    };

    // A listener of root at the abstract name of 10.66.0.2:port.
    let squatter = std::os::unix::net::UnixListener::bind_addr(&abstract_name(port)).unwrap();
    let out = program(
        "own_connect",
        r#"if(connect(s,(struct sockaddr*)&a,sizeof a)<0){
    printf("%s\n", errno==ECONNREFUSED?"refused":"error"); return 0;}
  printf("connected\n"); return 0;"#,
    )
    .arg(port.to_string())
    .output()
    .unwrap();
    drop(squatter);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.trim(),
        "refused",
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A client of root at the listener of the program of uid 65534.
    let mut server = program(
        "own_accept",
        r#"if(bind(s,(struct sockaddr*)&a,sizeof a)<0||listen(s,4)<0){perror("listen");return 1;}
  printf("ready\n"); fflush(stdout);
  sleep(1);
  fcntl(s,F_SETFL,fcntl(s,F_GETFL)|O_NONBLOCK);
  int c=accept(s,0,0);
  printf("%s\n", c>=0?"accepted":errno==EAGAIN?"eagain":"error"); return 0;"#,
    )
    .arg((port + 1).to_string())
    .stdout(Stdio::piped())
    .spawn()
    .unwrap();
    let mut lines = std::io::BufReader::new(server.stdout.take().unwrap()).lines();
    assert_eq!(lines.next().unwrap().unwrap(), "ready");
    let mut client =
        std::os::unix::net::UnixStream::connect_addr(&abstract_name(port + 1)).unwrap();
    let _ = client.write_all(b"x");
    let verdict = lines.next().unwrap().unwrap();
    let _ = server.wait();
    assert_eq!(verdict, "eagain");
}
