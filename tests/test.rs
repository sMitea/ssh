extern crate ssh;
use ssh::*;
use std::io::{Read, Write};

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
        s.request_exec(b"ls -l").unwrap();
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
fn read_remote_file() {
    let mut session = Session::new().unwrap();
    session.set_host(TEST_ADDR).unwrap();
    session.set_port(TEST_PORT).unwrap();
    session.set_username(TEST_USER).unwrap();
    session.connect().unwrap();
    println!("{:?}", session.is_server_known());
    session.userauth_password(TEST_PWD).unwrap();
    {
        let mut scp = session.scp_new(Mode::READ, "/tmp/blublu").unwrap();
        scp.init().unwrap();
        loop {
            match scp.pull_request().unwrap() {
                Request::NEWFILE => {
                    let mut buf: Vec<u8> = vec![];
                    scp.accept_request().unwrap();
                    scp.reader().read_to_end(&mut buf).unwrap();
                    println!("{:?}", std::str::from_utf8(&buf).unwrap());
                    break;
                }
                Request::WARNING => {
                    scp.deny_request().unwrap();
                    break;
                }
                _ => scp.deny_request().unwrap(),
            }
        }
    }
}
