#[warn(deprecated)]
extern crate libc;

extern crate libz_sys;
#[cfg(unix)]
extern crate openssl_sys;

use self::libc::{c_char, c_int, c_uint, c_void, size_t};
use libc::{c_uchar, c_ulonglong, uintmax_t};
use std::ffi::CString;
use std::fmt;
use std::io::{Read, Seek};
use std::path::Path;
use std::ptr::copy_nonoverlapping;
use std::time::Duration;

#[macro_use]
extern crate log;

#[macro_use]
extern crate bitflags;

#[allow(missing_copy_implementations)]
enum Session_ {}

unsafe impl Send for Session {}
unsafe impl Sync for Session {}

extern "C" {
    fn ssh_new() -> *mut Session_;
    fn ssh_free(s: *mut Session_);
    fn ssh_connect(s: *mut Session_) -> c_int;
    fn ssh_disconnect(s: *mut Session_) -> c_int;
    fn ssh_options_set(s: *mut Session_, t: c_int, v: *const c_void) -> c_int;
    fn ssh_options_parse_config(s: *mut Session_, v: *const c_char) -> c_int;
    fn ssh_get_error(s: *const c_void) -> *const c_char;
    fn ssh_get_error_code(s: *const c_void) -> c_int;
    fn ssh_userauth_agent(s: *mut Session_, user: *const c_char) -> c_int;
    fn ssh_userauth_password(s: *mut Session_, user: *const c_char, p: *const c_char) -> c_int;
    fn ssh_userauth_kbdint(s: *mut Session_, user: *const c_char, p: *const c_char) -> c_int;
    fn ssh_userauth_publickey_auto(
        s: *mut Session_,
        user: *const c_char,
        p: *const c_char,
    ) -> c_int;
    fn ssh_is_server_known(s: *mut Session_) -> c_int;
    fn ssh_write_knownhost(s: *mut Session_) -> c_int;
    fn ssh_get_pubkey_hash(s: *mut Session_, h: *mut *mut u8) -> c_int;
    fn ssh_clean_pubkey_hash(h: *mut *mut u8);
}

pub struct Session {
    session: *mut Session_,
}
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "Session{{..}}")
    }
}

#[allow(dead_code)]
#[repr(C)]
enum SshOptions {
    HOST,
    PORT,
    PortStr,
    FD,
    USER,
    SshDir,
    IDENTITY,
    AddIdentity,
    KNOWNHOSTS,
    TIMEOUT,
    TimeoutUsec,
    SSH1,
    SSH2,
    LogVerbosity,
    LogVerbosityStr,
    CiphersCS,
    CiphersSC,
    CompressionCS,
    CompressionSC,
    PROXYCOMMAND,
    BINDADDR,
    STRICTHOSTKEYCHECK,
    COMPRESSION,
    CompressionLevel,
    KeyExchange,
    HOSTKEYS,
    GssapiServerIdentity,
    GssapiClientIdentity,
    GssapiDelegateCredentials,
}

fn path_as_ptr(p: &Path) -> CString {
    let p = p.to_str().unwrap();
    std::ffi::CString::new(p).unwrap()
}

#[derive(Debug)]
pub struct Error {
    pub code: i32,
    pub msg: String,
}

fn err(session: &Session) -> Error {
    let msg = unsafe {
        let err = ssh_get_error(session.session as *const c_void);
        let slice = std::slice::from_raw_parts(err as *const u8, libc::strlen(err));
        std::str::from_utf8(slice).unwrap().to_string()
    };
    let code = unsafe { ssh_get_error_code(session.session as *const c_void) };
    Error { code, msg }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl std::error::Error for Error {}
const SSH_OK: c_int = 0;

impl Session {
    pub fn new() -> Result<Session, ()> {
        let session = unsafe { ssh_new() };
        if session.is_null() {
            Err(())
        } else {
            Ok(Session { session })
        }
    }
    pub fn set_host(&mut self, v: &str) -> Result<(), Error> {
        let v = std::ffi::CString::new(v).unwrap();
        let e = unsafe {
            ssh_options_set(
                self.session,
                SshOptions::HOST as c_int,
                v.as_ptr() as *const c_void,
            )
        };
        if e == SSH_OK {
            Ok(())
        } else {
            Err(err(self))
        }
    }
    pub fn set_port(&mut self, v: usize) -> Result<(), Error> {
        let v = [v as c_uint];
        let e = unsafe {
            ssh_options_set(
                self.session,
                SshOptions::PORT as c_int,
                v.as_ptr() as *const c_void,
            )
        };
        if e == SSH_OK {
            Ok(())
        } else {
            Err(err(self))
        }
    }

    /// set a timeout for the connection in seconds
    pub fn set_timeout(&mut self, timeout: usize) -> Result<(), Error> {
        let v = [timeout as c_uint];
        let e = unsafe {
            ssh_options_set(
                self.session,
                SshOptions::TIMEOUT as c_int,
                v.as_ptr() as *const c_void,
            )
        };
        if e == SSH_OK {
            Ok(())
        } else {
            Err(err(self))
        }
    }

    pub fn set_username(&mut self, v: &str) -> Result<(), Error> {
        let v = std::ffi::CString::new(v).unwrap();
        let e = unsafe {
            ssh_options_set(
                self.session,
                SshOptions::USER as c_int,
                v.as_ptr() as *const c_void,
            )
        };
        if e == SSH_OK {
            Ok(())
        } else {
            Err(err(self))
        }
    }
    /// Set the location of the ".ssh" directory, where the config file and keys can be found (it may include "%s", which will be replaced by the user home directory).
    pub fn set_ssh_dir<P: AsRef<Path>>(&mut self, v: P) -> Result<(), Error> {
        let e = unsafe {
            ssh_options_set(
                self.session,
                SshOptions::USER as c_int,
                path_as_ptr(v.as_ref()).as_ptr() as *const c_void,
            )
        };
        if e == SSH_OK {
            Ok(())
        } else {
            Err(err(self))
        }
    }
    /// Set the location of the "knownhosts" file (it may include "%s", which will be replaced by the user home directory).
    pub fn set_knownhosts<P: AsRef<Path>>(&mut self, v: P) -> Result<(), Error> {
        let e = unsafe {
            ssh_options_set(
                self.session,
                SshOptions::KNOWNHOSTS as c_int,
                path_as_ptr(v.as_ref()).as_ptr() as *const c_void,
            )
        };
        if e == SSH_OK {
            Ok(())
        } else {
            Err(err(self))
        }
    }
    /// Set the location of the key to be used for authentication (it may include "%s", which will be replaced by the user home directory).
    pub fn set_identity<P: AsRef<Path>>(&mut self, v: P) -> Result<(), Error> {
        let e = unsafe {
            ssh_options_set(
                self.session,
                SshOptions::IDENTITY as c_int,
                path_as_ptr(v.as_ref()).as_ptr() as *const c_void,
            )
        };
        if e == SSH_OK {
            Ok(())
        } else {
            Err(err(self))
        }
    }
    /// Allow version 1 of the protocol (default unspecified).
    pub fn set_ssh1(&mut self, v: bool) -> Result<(), Error> {
        let v: [c_int; 1] = [if v { 1 } else { 0 }];
        let e = unsafe {
            ssh_options_set(
                self.session,
                SshOptions::SSH1 as c_int,
                v.as_ptr() as *const c_void,
            )
        };
        if e == SSH_OK {
            Ok(())
        } else {
            Err(err(self))
        }
    }
    /// Allow version 2 of the protocol (default unspecified).
    pub fn set_ssh2(&mut self, v: bool) -> Result<(), Error> {
        let v: [c_int; 1] = [if v { 1 } else { 0 }];
        let e = unsafe {
            ssh_options_set(
                self.session,
                SshOptions::SSH2 as c_int,
                v.as_ptr() as *const c_void,
            )
        };
        if e == SSH_OK {
            Ok(())
        } else {
            Err(err(self))
        }
    }
    /// Parse configuration file. If the path is `None`, then `~/.ssh/config` is read.
    pub fn parse_config(&mut self, path: Option<&Path>) -> Result<(), Error> {
        let e = unsafe {
            ssh_options_parse_config(
                self.session,
                match path {
                    Some(p) => path_as_ptr(p).as_ptr() as *const c_char,
                    None => std::ptr::null_mut(),
                },
            )
        };
        if e == SSH_OK {
            Ok(())
        } else {
            Err(err(self))
        }
    }

    /// Check whether the remote server's key is known.
    pub fn is_server_known(&self) -> Result<ServerKnown, Error> {
        let e = unsafe { ssh_is_server_known(self.session) };
        if e >= 0 {
            Ok(unsafe { std::mem::transmute(e) })
        } else {
            Err(err(self))
        }
    }
    /// Accept the remote server's key.
    pub fn write_knownhost(&mut self) -> Result<(), Error> {
        let e = unsafe { ssh_write_knownhost(self.session) };
        if e == SSH_OK {
            Ok(())
        } else {
            Err(err(self))
        }
    }
    /// Get a hash of the server's public key
    pub fn get_pubkey_hash(&self) -> Result<Vec<u8>, Error> {
        let mut ptr = std::ptr::null_mut();
        let e = unsafe { ssh_get_pubkey_hash(self.session, std::mem::transmute(&mut ptr)) };
        if e >= 0 {
            let mut v = vec![0; e as usize];
            unsafe {
                copy_nonoverlapping(ptr, v.as_mut_ptr(), e as usize);
                ssh_clean_pubkey_hash(std::mem::transmute(&mut ptr))
            }
            Ok(v)
        } else {
            unsafe { ssh_clean_pubkey_hash(std::mem::transmute(&mut ptr)) }
            Err(err(self))
        }
    }
    pub fn connect(&mut self) -> Result<(), Error> {
        let e = unsafe { ssh_connect(self.session) };
        if e == SSH_OK {
            Ok(())
        } else {
            Err(err(self))
        }
    }
    /// Disconnect the session. The session can be reused later to open a new session.
    pub fn disconnect(&mut self) -> Result<(), Error> {
        let e = unsafe { ssh_disconnect(self.session) };
        if e == SSH_OK {
            Ok(())
        } else {
            Err(err(self))
        }
    }
    /// Authenticate with a password.
    pub fn userauth_password(&mut self, p: &str) -> Result<(), Error> {
        let p = std::ffi::CString::new(p).unwrap();
        let e = unsafe {
            ssh_userauth_password(self.session, std::ptr::null_mut(), p.as_ptr() as *const _)
        };
        if e == SSH_OK {
            Ok(())
        } else {
            Err(err(self))
        }
    }

    pub fn userauth_agent(&mut self) -> Result<(), Error> {
        let e = unsafe { ssh_userauth_agent(self.session, std::ptr::null_mut()) };
        if e == SSH_OK {
            Ok(())
        } else {
            Err(err(self))
        }
    }

    /// Print a prompt on the standard output, and then ask the user a password on the standard input. The typed password is not echoed.
    pub fn userauth_kbdint(&mut self, user: Option<&str>) -> Result<(), Error> {
        let e = match user {
            None => unsafe {
                ssh_userauth_kbdint(self.session, std::ptr::null_mut(), std::ptr::null_mut())
            },
            Some(p) => {
                let p = std::ffi::CString::new(p).unwrap();
                unsafe {
                    ssh_userauth_kbdint(self.session, p.as_ptr() as *const _, std::ptr::null_mut())
                }
            }
        };
        if e == SSH_OK {
            Ok(())
        } else {
            Err(err(self))
        }
    }
    /// Print a prompt on the standard output, and then ask the user a password on the standard input. The typed password is not echoed.
    pub fn userauth_publickey_auto(&mut self, p: Option<&str>) -> Result<(), Error> {
        let e = match p {
            None => unsafe {
                ssh_userauth_publickey_auto(
                    self.session,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            Some(p) => {
                let p = std::ffi::CString::new(p).unwrap();
                unsafe {
                    ssh_userauth_publickey_auto(
                        self.session,
                        std::ptr::null_mut(),
                        p.as_ptr() as *const _,
                    )
                }
            }
        };
        if e == SSH_OK {
            Ok(())
        } else {
            Err(err(self))
        }
    }
    /// Start an SCP connection.
    pub fn scp_new<'b, P: AsRef<Path>>(&'b self, mode: Mode, v: P) -> Result<Scp<'b>, Error> {
        let scp = unsafe {
            ssh_scp_new(
                self.session,
                mode.bits(),
                path_as_ptr(v.as_ref()).as_ptr() as *const _,
            )
        };
        if scp.is_null() {
            Err(err(self))
        } else {
            Ok(Scp {
                session: self,
                scp: scp,
                size: 0,
            })
        }
    }
    /// Start a channel to issue remote commands.
    pub fn channel_new<'b>(&'b self) -> Result<Channel<'b>, Error> {
        let e = unsafe { ssh_channel_new(self.session) };
        if e.is_null() {
            Err(err(self))
        } else {
            Ok(Channel {
                session: self,
                channel: e,
            })
        }
    }

    pub fn sftp_new(&self) -> Result<Sftp, Error> {
        let sftp = unsafe { sftp_new(self.session) };
        if sftp.is_null() {
            Err(err(self))
        } else {
            Ok(Sftp {
                session: self,
                sftp,
            })
        }
    }

    pub fn mkdir<P: AsRef<Path>>(&self, path: P, mode: usize) -> Result<Sftp, Error> {
        let p = path_as_ptr(path.as_ref());
        let sftp = unsafe { sftp_mkdir(self.session, p.as_ptr() as *const _, mode as c_int) };
        if sftp.is_null() {
            Err(err(self))
        } else {
            Ok(Sftp {
                session: self,
                sftp,
            })
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        debug!("ssh_free");
        unsafe { ssh_free(self.session) }
    }
}

#[derive(Debug)]
#[repr(C)]
pub enum ServerKnown {
    /// The key is unknown
    NotKnown = 0,
    /// The key is known
    Known,
    /// The key has changed since the last connection. You have to warn the user about a possible attack.
    Changed,
    /// The type of the key has changed. Possible attack.
    FoundOther,
    /// The known hosts file doesn't exist, and will be created when `write_knownhost` is called.
    FileNotFound,
}

impl ServerKnown {
    pub fn is_known(&self) -> bool {
        match *self {
            ServerKnown::Known => true,
            _ => false,
        }
    }
}

#[allow(missing_copy_implementations)]
enum Channel_ {}

extern "C" {
    fn ssh_channel_new(s: *mut Session_) -> *mut Channel_;
    fn ssh_channel_close(s: *mut Channel_) -> c_int;
    fn ssh_channel_free(s: *mut Channel_);
    fn ssh_channel_open_session(s: *mut Channel_) -> c_int;
    fn ssh_channel_request_exec(s: *mut Channel_, b: *const c_char) -> c_int;
    fn ssh_channel_read(s: *mut Channel_, b: *mut c_char, c: size_t, is_stderr: c_int) -> c_int;
    fn ssh_channel_read_timeout(
        s: *mut Channel_,
        b: *mut c_char,
        c: size_t,
        is_stderr: c_int,
        timeout_ms: c_int,
    ) -> c_int;
    fn ssh_channel_send_eof(s: *mut Channel_) -> c_int;
    fn ssh_channel_get_exit_status(s: *const Channel_) -> c_int;
}

pub struct Channel<'b> {
    session: &'b Session,
    channel: *mut Channel_,
}

impl<'b> Channel<'b> {
    pub fn open_session(&self) -> Result<(), Error> {
        let e = unsafe { ssh_channel_open_session(self.channel) };
        if e == 0 {
            Ok(())
        } else {
            Err(err(self.session))
        }
    }
}

pub struct ChannelReader<'d, 'c: 'd> {
    channel: &'d Channel<'c>,
    is_stderr: c_int,
}

impl<'d, 'c: 'd> Channel<'c> {
    pub fn request_exec(&mut self, cmd: &[u8]) -> Result<(), Error> {
        let str = std::ffi::CString::new(cmd).unwrap();
        let e = unsafe { ssh_channel_request_exec(self.channel, str.as_ptr() as *const _) };
        if e == SSH_OK {
            Ok(())
        } else {
            Err(err(self.session))
        }
    }
    pub fn send_eof(&mut self) -> Result<(), Error> {
        let e = unsafe { ssh_channel_send_eof(self.channel) };
        if e == 0 {
            Ok(())
        } else {
            Err(err(self.session))
        }
    }
    pub fn get_exit_status(&self) -> Option<c_int> {
        let e = unsafe { ssh_channel_get_exit_status(self.channel) };
        if e < 0 {
            None
        } else {
            Some(e)
        }
    }
    pub fn stdout(&'d mut self) -> ChannelReader<'d, 'c> {
        ChannelReader {
            channel: self,
            is_stderr: 0,
        }
    }
    pub fn stderr(&'d mut self) -> ChannelReader<'d, 'c> {
        ChannelReader {
            channel: self,
            is_stderr: 1,
        }
    }
    pub fn close(&mut self) {
        unsafe { ssh_channel_close(self.channel) };
    }
}

impl<'b> Drop for Channel<'b> {
    fn drop(&mut self) {
        debug!("ssh_channel_free");
        unsafe { ssh_channel_free(self.channel) };
    }
}

impl<'d, 'c> ChannelReader<'d, 'c> {
    pub fn read_timeout(
        &mut self,
        buf: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, std::io::Error> {
        let ms = timeout.as_millis();
        let e = unsafe {
            ssh_channel_read_timeout(
                self.channel.channel,
                buf.as_mut_ptr() as *mut c_char,
                buf.len() as size_t,
                self.is_stderr,
                ms as c_int,
            )
        };
        if e >= 0 {
            Ok(e as usize)
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

impl<'d, 'c> Read for ChannelReader<'d, 'c> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        let e = unsafe {
            ssh_channel_read(
                self.channel.channel,
                buf.as_mut_ptr() as *mut c_char,
                buf.len() as size_t,
                self.is_stderr,
            )
        };
        if e >= 0 {
            Ok(e as usize)
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

extern "C" {
    fn ssh_scp_new(s: *mut Session_, mode: c_int, location: *const c_char) -> *mut Scp_;
    fn ssh_scp_init(s: *mut Scp_) -> c_int;
    fn ssh_scp_free(s: *mut Scp_) -> c_int;
    fn ssh_scp_close(s: *mut Scp_) -> c_int;
    fn ssh_scp_pull_request(s: *mut Scp_) -> c_int;
    fn ssh_scp_accept_request(s: *mut Scp_) -> c_int;
    fn ssh_scp_deny_request(s: *mut Scp_) -> c_int;
    fn ssh_scp_read(s: *mut Scp_, b: *mut c_char, st: size_t) -> c_int;
    fn ssh_scp_push_file64(s: *mut Scp_, b: *const c_char, st: u64, mode: c_int) -> c_int;
    fn ssh_scp_push_directory(s: *mut Scp_, b: *const c_char, mode: c_int) -> c_int;
    fn ssh_scp_write(s: *mut Scp_, b: *const c_char, st: size_t) -> c_int;
    fn ssh_scp_request_get_size64(s: *mut Scp_) -> u64;
    fn ssh_scp_request_get_permissions(s: *mut Scp_) -> c_int;
    fn ssh_scp_request_get_filename(s: *mut Scp_) -> *const c_char;
    fn ssh_scp_request_get_warning(s: *mut Scp_) -> *const c_char;
    fn ssh_scp_leave_directory(s: *mut Scp_) -> c_int;
}

#[allow(missing_copy_implementations)]
enum Scp_ {}

/// File transfer over SSH.
pub struct Scp<'b> {
    session: &'b Session,
    scp: *mut Scp_,
    size: usize,
}

bitflags! {
    pub struct Mode:c_int {
        const WRITE = 0x0;
        const READ = 0x1;
        const RECURSIVE = 0x10;
    }
}

#[repr(C)]
#[derive(Debug)]
pub enum Request {
    /** A new directory is going to be pulled */
    NEWDIR = 1,
    /** A new file is going to be pulled */
    NEWFILE,
    /** End of requests */
    EOF,
    /** End of directory */
    ENDDIR,
    /** Warning received */
    WARNING,
}

impl<'b> Drop for Scp<'b> {
    fn drop(&mut self) {
        unsafe {
            debug!("ssh_scp_free");
            ssh_scp_free(self.scp);
        }
    }
}

impl<'b> Scp<'b> {
    pub fn init(&mut self) -> Result<(), Error> {
        let e = unsafe { ssh_scp_init(self.scp) };
        if e == 0 {
            Ok(())
        } else {
            Err(err(self.session))
        }
    }
    pub fn close(&mut self) {
        unsafe {
            ssh_scp_close(self.scp);
        }
    }

    pub fn pull_request(&mut self) -> Result<Request, Error> {
        unsafe {
            let e = ssh_scp_pull_request(self.scp);
            if e >= 1 && e <= 5 {
                Ok(std::mem::transmute(e))
            } else {
                Err(err(self.session))
            }
        }
    }
    pub fn push_file<P: AsRef<Path>>(
        &mut self,
        path: P,
        size: usize,
        mode: usize,
    ) -> Result<(), Error> {
        unsafe {
            let p = path_as_ptr(path.as_ref());
            let e =
                ssh_scp_push_file64(self.scp, p.as_ptr() as *const _, size as u64, mode as c_int);
            if e == 0 {
                Ok(())
            } else {
                Err(err(self.session))
            }
        }
    }
    pub fn push_directory<P: AsRef<Path>>(&mut self, path: P, mode: usize) -> Result<(), Error> {
        unsafe {
            let p = path_as_ptr(path.as_ref());
            let e = ssh_scp_push_directory(self.scp, p.as_ptr() as *const _, mode as c_int);
            if e == 0 {
                Ok(())
            } else {
                Err(err(self.session))
            }
        }
    }
    pub fn request_get_size(&mut self) -> usize {
        unsafe { ssh_scp_request_get_size64(self.scp) as usize }
    }
    pub fn request_get_permissions(&mut self) -> Result<usize, Error> {
        let e = unsafe { ssh_scp_request_get_permissions(self.scp) };
        if e >= 0 {
            Ok(e as usize)
        } else {
            Err(err(self.session))
        }
    }
    pub fn request_get_filename(&mut self) -> Result<&'b [u8], Error> {
        let e = unsafe { ssh_scp_request_get_filename(self.scp) };
        if e.is_null() {
            Err(err(self.session))
        } else {
            Ok(unsafe { std::slice::from_raw_parts(e as *const u8, libc::strlen(e)) })
        }
    }
    pub fn request_get_warning(&mut self) -> Result<&'b [u8], Error> {
        let e = unsafe { ssh_scp_request_get_warning(self.scp) };
        if e.is_null() {
            Err(err(self.session))
        } else {
            Ok(unsafe { std::slice::from_raw_parts(e as *const u8, libc::strlen(e)) })
        }
    }
    pub fn accept_request(&mut self) -> Result<(), Error> {
        let e = unsafe { ssh_scp_accept_request(self.scp) };
        if e == 0 {
            Ok(())
        } else {
            Err(err(self.session))
        }
    }
    pub fn deny_request(&mut self) -> Result<(), Error> {
        let e = unsafe { ssh_scp_deny_request(self.scp) };
        if e == 0 {
            Ok(())
        } else {
            Err(err(self.session))
        }
    }
    pub fn leave_directory(&mut self) -> Result<(), Error> {
        let e = unsafe { ssh_scp_leave_directory(self.scp) };
        if e == 0 {
            Ok(())
        } else {
            Err(err(self.session))
        }
    }

    /// Initialize the Scp structure to use as a Reader. Not doing so will cause `read` to fail.
    pub fn reader(&mut self) -> &mut Scp<'b> {
        self.size = self.request_get_size();
        self
    }
}

impl<'c> std::io::Read for Scp<'c> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        if self.size == 0 {
            Ok(0)
        } else {
            let e = unsafe {
                ssh_scp_read(
                    self.scp,
                    buf.as_mut_ptr() as *mut c_char,
                    buf.len() as size_t,
                )
            };
            if e >= 0 {
                self.size -= e as usize;
                Ok(e as usize)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    err(self.session),
                ))
            }
        }
    }
}

impl<'c> std::io::Write for Scp<'c> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        let e =
            unsafe { ssh_scp_write(self.scp, buf.as_ptr() as *mut c_char, buf.len() as size_t) };
        if e >= 0 {
            Ok(e as usize)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                err(self.session),
            ))
        }
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

#[allow(missing_copy_implementations)]
enum Sftp_ {}

pub struct Sftp<'b> {
    session: &'b Session,
    sftp: *mut Sftp_,
}

impl<'b> Drop for Sftp<'b> {
    fn drop(&mut self) {
        unsafe {
            sftp_free(self.sftp);
        }
    }
}

extern "C" {
    fn sftp_new(s: *mut Session_) -> *mut Sftp_;
    fn sftp_mkdir(s: *mut Session_, path: *const c_char, mode: c_int) -> *mut Sftp_;
    fn sftp_stat(s: *mut Sftp_, path: *const c_char) -> *mut LIBSSH_SFTP_ATTRIBUTES;
    fn sftp_init(s: *mut Sftp_) -> c_int;
    fn sftp_free(s: *mut Sftp_);
}

impl<'b> Sftp<'b> {
    pub fn init(&mut self) -> Result<(), Error> {
        let e = unsafe { sftp_init(self.sftp) };
        if e == 0 {
            Ok(())
        } else {
            Err(err(self.session))
        }
    }

    pub fn open<P: AsRef<Path>>(
        &mut self,
        path: P,
        access: usize,
        mode: usize,
    ) -> Result<SftpFile, Error> {
        let p = path_as_ptr(path.as_ref());

        let stat = unsafe { sftp_stat(self.sftp, p.as_ptr() as *const _) };
        if stat.is_null() {
            return Err(err(self.session));
        };
        let size = if !stat.is_null() {
            let size = unsafe { (*stat).size };
            unsafe{
                libc::free(stat as *mut libc::c_void);
            }
            size
        } else {
            0_u64
        };
        let file = unsafe {
            sftp_open(
                self.sftp,
                p.as_ptr() as *const _,
                access as c_int,
                mode as c_int,
            )
        };
        if file.is_null() {
            return Err(err(self.session));
        } else {
            
            Ok(SftpFile {
                sftp: self,
                file,
                size,
            })
        }
    }
}

pub struct SftpFile<'b> {
    sftp: &'b Sftp<'b>,
    file: *mut SftpFile_,
    size: u64,
}

#[allow(missing_copy_implementations)]
enum SftpFile_ {}

extern "C" {
    fn sftp_close(s: *mut SftpFile_) -> c_int;
    fn sftp_open(s: *mut Sftp_, b: *const c_char, c: c_int, mode: c_int) -> *mut SftpFile_;
    fn sftp_read(s: *mut SftpFile_, b: *mut c_void, st: size_t) -> c_int;
    fn sftp_seek64(s: *mut SftpFile_, new_offset: c_ulonglong) -> c_int;
    fn sftp_tell64(s: *mut SftpFile_) -> uintmax_t;
    fn sftp_write(s: *mut SftpFile_, b: *const c_char, st: size_t) -> c_int;
}

#[repr(C)]
struct LIBSSH_SFTP_ATTRIBUTES {
    name: *const c_char,
    longname: *const c_char,
    flags: c_uint,
    type_: c_uchar,
    size: c_ulonglong,
    uid: c_uint,
    gid: c_uint,
    owner: *const c_char,
    group: *const c_char,
    permissions: c_uint,
    atime64: c_ulonglong,
    atime: c_uint,
    atime_nseconds: c_uint,
    createtime: c_ulonglong,
    createtime_nseconds: c_uint,
    mtime64: c_ulonglong,
    mtime: c_uint,
    mtime_nseconds: c_uint,
}

impl<'b> SftpFile<'b> {
    pub fn get_size(&self) -> u64 {
        self.size
    }
}

impl<'b> Drop for SftpFile<'b> {
    fn drop(&mut self) {
        unsafe {
            sftp_close(self.file);
        }
    }
}

impl<'b> Read for SftpFile<'b> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        if self.size <= 0 {
            return Ok(0);
        }
        let e = unsafe {
            sftp_read(
                self.file,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as size_t,
            )
        };
        if e >= 0 {
            Ok(e as usize)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                err(self.sftp.session),
            ))
        }
    }
}

impl<'c> std::io::Write for SftpFile<'c> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        let e = unsafe { sftp_write(self.file, buf.as_ptr() as *mut c_char, buf.len() as size_t) };
        if e >= 0 {
            Ok(e as usize)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                err(self.sftp.session),
            ))
        }
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

impl<'b> Seek for SftpFile<'b> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        match pos {
            std::io::SeekFrom::Current(index) => unsafe {
                let position = sftp_tell64(self.file);
                println!("position: {}", position);
                let tell = if (index < 0) && (position > 0) {
                    (position as i128) + (index as i128)
                } else {
                    index as i128
                };
                let e = sftp_seek64(self.file, tell as u64);

                if e < 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        err(self.sftp.session),
                    ));
                }
            },
            std::io::SeekFrom::Start(index) => {
                let e = unsafe { sftp_seek64(self.file, index) };
                if e < 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        err(self.sftp.session),
                    ));
                }
            }
            std::io::SeekFrom::End(index) => unsafe {
                let tell = (self.size as i128) - (index as i128);
                let e = sftp_seek64(self.file, tell as u64);

                if e < 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        err(self.sftp.session),
                    ));
                }
            },
        };
        Ok(0)
    }
}
