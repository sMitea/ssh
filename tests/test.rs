extern crate ssh;
use ssh::*;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};

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
fn create_remote_file() {
    let mut session = Session::new().unwrap();
    session.set_host(TEST_ADDR).unwrap();
    session.set_port(TEST_PORT).unwrap();
    session.set_username(TEST_USER).unwrap();
    session.connect().unwrap();
    println!("{:?}", session.is_server_known());
    session.userauth_password(TEST_PWD).unwrap();
    {
        let mut scp = session.scp_new(Mode::WRITE, "/tmp").unwrap();
        scp.init().unwrap();
        let buf = b"blabla blibli\n".to_vec();
        scp.push_file("blublu", buf.len(), 0o644).unwrap();
        scp.write(&buf).unwrap();
    }
}

#[test]
fn create_remote_dir() {
    let mut session = Session::new().unwrap();
    session.set_host(TEST_ADDR).unwrap();
    session.set_port(TEST_PORT).unwrap();
    session.set_username(TEST_USER).unwrap();
    session.connect().unwrap();
    println!("{:?}", session.is_server_known());
    session.userauth_password(TEST_PWD).unwrap();
    {
        let mut scp = session
            .scp_new(Mode::RECURSIVE | Mode::WRITE, "/tmp")
            .unwrap();
        scp.init().unwrap();
        scp.push_directory("testdir", 0o755).unwrap();
        let buf = b"blabla\n".to_vec();
        scp.push_file("test file", buf.len(), 0o644).unwrap();
        scp.write(&buf).unwrap();
    }
}

#[test]
fn sftp() {
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
