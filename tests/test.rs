extern crate ssh;
use ssh::*;
use std::{
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    time::Duration,
};

const TEST_ADDR: &str = "127.0.0.1";
const TEST_PORT: usize = 49160;
const TEST_USER: &str = "root";
const TEST_PWD: &str = "admin";

#[test]
fn connect() {
    let mut session = Session::new().unwrap();
    session.set_host(TEST_ADDR).unwrap();
    session.set_port(TEST_PORT).unwrap();
    session.set_username(TEST_USER).unwrap();
    session.connect().unwrap();
    println!("{:?}", session.is_server_known());
    session.userauth_password(TEST_PWD).unwrap();
}

#[test]
fn run_cmd() {
    let mut session = Session::new().unwrap();
    session.set_host(TEST_ADDR).unwrap();
    session.set_port(TEST_PORT).unwrap();
    session.set_username(TEST_USER).unwrap();
    session.connect().unwrap();
    println!("{:?}", session.is_server_known());
    session.userauth_password(TEST_PWD).unwrap();
    {
        let mut s = session.channel_new().unwrap();
        s.open_session().unwrap();
        s.request_exec(b"echo Hello world").unwrap();
        s.send_eof().unwrap();
        let mut buf = Vec::new();
        s.stdout().read_to_end(&mut buf).unwrap();
        println!("{:?}", std::str::from_utf8(&buf).unwrap());
    }
}

#[test]
fn run_cmd_with_timeout() {
    let mut session = Session::new().unwrap();
    session.set_host(TEST_ADDR).unwrap();
    session.set_port(TEST_PORT).unwrap();
    session.set_username(TEST_USER).unwrap();
    session.connect().unwrap();
    println!("{:?}", session.is_server_known());
    session.userauth_password(TEST_PWD).unwrap();
    {
        let mut s = session.channel_new().unwrap();
        s.open_session().unwrap();
        s.request_exec(b"sleep 10;echo Hello world").unwrap();
        s.send_eof().unwrap();
        let mut buf = [0u8; 1024];
        s.stdout()
            .read_timeout(&mut buf, Duration::from_secs(2))
            .unwrap();
        println!("{:?}", std::str::from_utf8(&buf).unwrap());
    }
}

#[test]
fn sftp_read() {
    let mut session = Session::new().unwrap();
    session.set_host(TEST_ADDR).unwrap();
    session.set_port(TEST_PORT).unwrap();
    session.set_username(TEST_USER).unwrap();
    session.connect().unwrap();
    println!("{:?}", session.is_server_known());
    session.userauth_password(TEST_PWD).unwrap();
    {
        let mut sftp = session.sftp_new().unwrap();
        sftp.init().unwrap();
        let file = sftp
            .open("/etc/hosts", libc::O_RDONLY as usize, 0700)
            .unwrap();
        let mut buffer = BufReader::new(file);
        buffer.seek(SeekFrom::End(20)).unwrap();

        let lines = buffer.lines();
        for line in lines {
            println!("output: {}", line.unwrap());
        }
    }
}

#[test]
fn sftp_write() {
    let mut session = Session::new().unwrap();
    session.set_host(TEST_ADDR).unwrap();
    session.set_port(TEST_PORT).unwrap();
    session.set_username(TEST_USER).unwrap();
    session.connect().unwrap();
    println!("{:?}", session.is_server_known());
    session.userauth_password(TEST_PWD).unwrap();
    {
        let mut sftp = session.sftp_new().unwrap();
        sftp.init().unwrap();
        let mut file = sftp
            .open("/tmp/test", (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as usize, 0700)
            .unwrap();
        let buf = b"blabla\n".to_vec();
        file.write(&buf).unwrap();
    }
}

#[test]
fn sftp_write() {
    let mut session = Session::new().unwrap();
    session.set_host(TEST_ADDR).unwrap();
    session.set_port(TEST_PORT).unwrap();
    session.set_username(TEST_USER).unwrap();
    session.connect().unwrap();
    println!("{:?}", session.is_server_known());
    session.userauth_password(TEST_PWD).unwrap();
    {
        let mut sftp = session.sftp_new().unwrap();
        sftp.init().unwrap();
        let mut file = sftp
            .open("/tmp/test", (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as usize, 0700)
            .unwrap();
        let buf = b"blabla\n".to_vec();
        file.write(&buf).unwrap();
    }
}
