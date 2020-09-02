extern crate ssh;

use ssh::*;
use std::{
    env,
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    time::Duration,
};

pub fn authed_session() -> Result<Session, ssh::Error> {
    let mut session = Session::new().unwrap();
    let port = env::var("RUST_SSH2_FIXTURE_PORT")
        .map(|s| s.parse().unwrap())
        .unwrap_or(22);
    let user = env::var("USER").unwrap();
    session.set_host("127.0.0.1")?;
    session.set_port(port)?;
    session.set_username(&user)?;
    session.connect().unwrap();
    session.userauth_agent()?;
    Ok(session)
}

#[test]
fn run_cmd() {
    let session = authed_session().unwrap();
    {
        let mut s = session.channel_new().unwrap();
        s.open_session().unwrap();
        s.request_exec(b"echo Hello world").unwrap();
        s.send_eof().unwrap();
        let mut buf = Vec::new();
        s.stdout().read_to_end(&mut buf).unwrap();
        assert_eq!(
            "Hello world\n".to_string(),
            std::str::from_utf8(&buf).unwrap()
        );
    }
}

#[test]
fn run_cmd_with_timeout() {
    let session = authed_session().unwrap();
    {
        let mut s = session.channel_new().unwrap();
        s.open_session().unwrap();
        s.request_exec(b"sleep 2;echo Hello world").unwrap();
        s.send_eof().unwrap();
        let mut buf = [0u8; 1024];
        assert!(
            s.stdout()
                .read_timeout(&mut buf, Duration::from_secs(1))
                .unwrap()
                == 0
        );
    }
}

#[test]
fn sftp_read() {
    let session = authed_session().unwrap();
    {
        std::fs::write("/tmp/read_test", "hello world").unwrap();
        let mut sftp = session.sftp_new().unwrap();
        sftp.init().unwrap();
        let file = sftp
            .open("/tmp/read_test", libc::O_RDONLY as usize, 0700)
            .unwrap();
        let mut buffer = BufReader::new(file);
        buffer.seek(SeekFrom::Start(5)).unwrap();

        let mut buf = String::new();
        buffer.read_line(&mut buf).unwrap();
        assert_eq!(" world".to_string(), buf);
        std::fs::remove_file("/tmp/read_test").unwrap();
    }
}

#[test]
fn sftp_write() {
    let session = authed_session().unwrap();
    {
        std::fs::write("/tmp/write_test", "hello world").unwrap();
        let mut sftp = session.sftp_new().unwrap();
        sftp.init().unwrap();
        let mut file = sftp
            .open(
                "/tmp/write_test",
                (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as usize,
                0700,
            )
            .unwrap();
        let buf = b"blabla\n".to_vec();
        file.write(&buf).unwrap();
        std::fs::remove_file("/tmp/write_test").unwrap();
    }
}