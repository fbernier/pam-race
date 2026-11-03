//! Minimal PAM application with a sudo-style terminal conversation, used by
//! the integration tests: `pam-race-host CONFDIR SERVICE USER`.
//!
//! Like sudo's tgetpass, a prompt reads /dev/tty with echo off after a
//! TCSAFLUSH, and EOF or an interrupted read is a conversation error. With
//! `PAM_RACE_TEST_READER=sudo-rs` it reads like sudo-rs instead: byte by
//! byte in non-canonical mode, terminal set and restored with TCSANOW.
//! When pam_authenticate returns it prints `CHILDREN <n>` (child processes
//! it still has, zombies included) and `RESULT <pam return code>`. It prints
//! `REAPED <pid>` for any child its `waitpid(-1)` collects: a host may reap
//! its children at any time, and the module's must not be among them. It is
//! also a child subreaper (as service managers and container inits are), so
//! orphans of the module's processes would come to it, and be reaped.
//!
//! Fault injection: `PAM_RACE_TEST_DENY=SYSCALL[:LEN][/ENOSYS]` makes that
//! syscall (`close_range`, `setsid`, `sendto` or `clone3`) fail with EPERM,
//! or ENOSYS, in this process and everything it starts; with `:LEN`, only
//! calls whose third argument (the length, for sendto) is LEN.

use std::ffi::{CStr, CString, c_int, c_void};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::ptr;

use pam_race::ffi::*;

fn tty() -> std::fs::File {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .expect("no controlling tty")
}

/// How a prompt reads the terminal, after a real host's password reader.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reader {
    /// sudo's tgetpass, and libpam_misc's misc_conv (su): canonical mode,
    /// set and restored with TCSAFLUSH.
    Sudo,
    /// sudo-rs: hidden input read byte by byte in non-canonical mode, set and
    /// restored with TCSANOW; VEOF on an empty line is a cancel.
    SudoRs,
}

impl Reader {
    fn from_env() -> Reader {
        match std::env::var("PAM_RACE_TEST_READER").as_deref() {
            Err(_) | Ok("sudo") => Reader::Sudo,
            Ok("sudo-rs") => Reader::SudoRs,
            Ok(r) => panic!("unknown reader {r}"),
        }
    }
}

fn read_line(tty: &mut std::fs::File, echo: bool) -> Option<Vec<u8>> {
    let reader = Reader::from_env();
    let fd = tty.as_raw_fd();
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    unsafe { libc::tcgetattr(fd, &mut saved) };
    let mut t = saved;
    if !echo {
        t.c_lflag &= !(libc::ECHO | libc::ECHONL);
    }
    let raw = reader == Reader::SudoRs && !echo;
    if raw {
        t.c_lflag &= !libc::ICANON;
        t.c_cc[libc::VMIN] = 1;
        t.c_cc[libc::VTIME] = 0;
    }
    let when = match reader {
        Reader::Sudo => libc::TCSAFLUSH,
        Reader::SudoRs => libc::TCSANOW,
    };
    unsafe { libc::tcsetattr(fd, when, &t) };
    let mut line = Vec::new();
    let ok = loop {
        let mut c = 0u8;
        match unsafe { libc::read(fd, (&raw mut c).cast(), 1) } {
            1 if c == b'\n' || c == b'\r' => break true,
            1 if raw && c == saved.c_cc[libc::VEOF] => break !line.is_empty(),
            1 => line.push(c),
            0 => break !line.is_empty(),
            _ => break false,
        }
    };
    unsafe { libc::tcsetattr(fd, when, &saved) };
    if !echo {
        let _ = tty.write_all(b"\n");
    }
    ok.then_some(line)
}

unsafe extern "C" fn converse(
    n: c_int,
    msg: *mut *const pam_message,
    resp: *mut *mut pam_response,
    _: *mut c_void,
) -> c_int {
    let mut tty = tty();
    let arr = unsafe { libc::calloc(n as usize, size_of::<pam_response>()) }.cast::<pam_response>();
    for i in 0..n as usize {
        let m = unsafe { &**msg.add(i) };
        let text = unsafe { CStr::from_ptr(m.msg) }.to_string_lossy();
        match m.msg_style {
            PAM_PROMPT_ECHO_OFF | PAM_PROMPT_ECHO_ON => {
                let _ = write!(tty, "{text}");
                let Some(line) = read_line(&mut tty, m.msg_style == PAM_PROMPT_ECHO_ON) else {
                    unsafe { libc::free(arr.cast()) };
                    return PAM_CONV_ERR;
                };
                unsafe { (*arr.add(i)).resp = libc::strdup(CString::new(line).unwrap().as_ptr()) };
            }
            _ => {
                let _ = writeln!(tty, "{text}");
            }
        }
    }
    unsafe { *resp = arr };
    PAM_SUCCESS
}

fn main() {
    let args: Vec<CString> = std::env::args()
        .skip(1)
        .map(|a| CString::new(a).unwrap())
        .collect();
    let [confdir, service, user] = &args[..] else {
        eprintln!("usage: pam-race-host CONFDIR SERVICE USER");
        std::process::exit(2);
    };
    if let Some(spec) = std::env::var_os("PAM_RACE_TEST_DENY") {
        deny(spec.to_str().expect("UTF-8 spec"));
    }
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) },
        0,
        "PR_SET_CHILD_SUBREAPER"
    );
    std::thread::spawn(|| {
        loop {
            let mut status = 0;
            match unsafe { libc::waitpid(-1, &mut status, 0) } {
                pid if pid > 0 => {
                    let _ = writeln!(tty(), "REAPED {pid}");
                }
                _ => std::thread::sleep(std::time::Duration::from_millis(5)),
            }
        }
    });
    let conv = pam_conv {
        conv: Some(converse),
        appdata_ptr: ptr::null_mut(),
    };
    let mut h = ptr::null_mut();
    let rc = unsafe {
        pam_start_confdir(
            service.as_ptr(),
            user.as_ptr(),
            &conv,
            confdir.as_ptr(),
            &mut h,
        )
    };
    assert_eq!(rc, PAM_SUCCESS, "pam_start");
    let rc = unsafe { pam_authenticate(h, 0) };
    unsafe { pam_end(h, rc) };
    let _ = writeln!(tty(), "CHILDREN {}", children());
    let _ = writeln!(tty(), "RESULT {rc}");
}

/// Children of every thread of this process, zombies included.
fn children() -> usize {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .map(|t| {
            std::fs::read_to_string(t.unwrap().path().join("children"))
                .unwrap()
                .split_whitespace()
                .count()
        })
        .sum()
}

/// Install a seccomp filter failing one syscall. Test-only: it does not
/// check the architecture field.
fn deny(spec: &str) {
    let (spec, errno) = match spec.split_once('/') {
        Some((s, "ENOSYS")) => (s, libc::ENOSYS),
        Some((_, e)) => panic!("unknown errno {e}"),
        None => (spec, libc::EPERM),
    };
    let (name, len) = match spec.split_once(':') {
        Some((n, l)) => (n, Some(l.parse::<u32>().expect("LEN"))),
        None => (spec, None),
    };
    let nr = match name {
        "close_range" => libc::SYS_close_range,
        "setsid" => libc::SYS_setsid,
        "sendto" => libc::SYS_sendto,
        "clone3" => libc::SYS_clone3,
        _ => panic!("unknown syscall {name}"),
    } as u32;
    let stmt = |code: u32, k: u32| libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    };
    let jeq = |k: u32, jf: u8| libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt: 0,
        jf,
        k,
    };
    let load = |offset: u32| stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, offset);
    let ret = |k: u32| stmt(libc::BPF_RET | libc::BPF_K, k);
    let fail = ret(libc::SECCOMP_RET_ERRNO | errno as u32);
    let allow = ret(libc::SECCOMP_RET_ALLOW);
    // seccomp_data: nr at 0, args[2] at 32 (low half on little-endian).
    let mut prog = match len {
        None => vec![load(0), jeq(nr, 1), fail, allow],
        Some(len) => vec![load(0), jeq(nr, 3), load(32), jeq(len, 1), fail, allow],
    };
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_mut_ptr(),
    };
    unsafe {
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        assert_eq!(
            libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &fprog),
            0,
            "seccomp: {}",
            std::io::Error::last_os_error()
        );
    }
}
