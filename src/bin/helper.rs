//! `pam-race-helper`: runs one PAM service's auth stack for pam_race.
//!
//! Started by the module with the conversation socket on fd 3, stdio on
//! /dev/null, in its own session, with the credentials of the host process
//! (for sudo: real UID = invoking user, effective UID = root). Not meant to
//! be run by hand; it holds no privilege of its own.

use std::ffi::{CStr, c_int, c_void};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::ExitCode;
use std::ptr;

use pam_race::ffi::*;
use pam_race::spawn::HELPER_FD;
use pam_race::types::*;
use pam_race::{proto, wire};

fn log(msg: &str) {
    if let Ok(m) = std::ffi::CString::new(msg) {
        unsafe { libc::syslog(libc::LOG_ERR, c"%s".as_ptr(), m.as_ptr()) };
    }
}

struct Ctx {
    sock: BorrowedFd<'static>,
    buf: Vec<u8>,
}

fn main() -> ExitCode {
    unsafe {
        // Rust's runtime ignores SIGPIPE; modules may spawn programs that
        // expect the default. Our own sends use MSG_NOSIGNAL.
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        // Holds passwords: no core dumps, no ptrace by the invoking user.
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
        // execve() cleared it if the host's credentials were mixed (sudo).
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        libc::openlog(
            c"pam-race-helper".as_ptr(),
            libc::LOG_PID,
            libc::LOG_AUTHPRIV,
        );
        // Modules translate their messages (gettext) but leave selecting
        // the locale to the application. The module passed only parsed
        // locale names (LocaleEnv).
        libc::setlocale(libc::LC_ALL, c"".as_ptr());
    }
    let sock = unsafe { BorrowedFd::borrow_raw(HELPER_FD) };
    let mut ty: c_int = 0;
    let mut len = size_of::<c_int>() as libc::socklen_t;
    let is_seqpacket = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&raw mut ty).cast(),
            &mut len,
        )
    } == 0
        && ty == libc::SOCK_SEQPACKET;
    if !is_seqpacket {
        eprintln!("pam-race-helper: internal helper of pam_race.so; not meant to be run directly");
        return ExitCode::from(2);
    }
    // dup2() left the socket inheritable: nothing a module starts may hold
    // it (to forge packets, or to keep it open past our death).
    if unsafe { libc::fcntl(HELPER_FD, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        log(&format!("FD_CLOEXEC: {}", std::io::Error::last_os_error()));
        return ExitCode::FAILURE;
    }

    let mut ctx = Ctx {
        sock,
        buf: vec![0u8; proto::MAX_PACKET],
    };
    let setup = match wire::recv(sock, &mut ctx.buf) {
        Ok(Some(pkt)) => match proto::decode_setup(pkt) {
            Ok(s) => s,
            Err(e) => {
                log(&e.to_string());
                return ExitCode::FAILURE;
            }
        },
        // The module gave up before we got going.
        Ok(None) => return ExitCode::FAILURE,
        Err(e) => {
            log(&format!("recv: {e}"));
            return ExitCode::FAILURE;
        }
    };
    // PDEATHSIG (armed again above: execve() may clear it) only fires if the
    // keeper dies after that; catch the window before it by checking whether
    // the module end is still open.
    let mut pfd = libc::pollfd {
        fd: sock.as_raw_fd(),
        events: 0,
        revents: 0,
    };
    if unsafe { libc::poll(&mut pfd, 1, 0) } != 0 && pfd.revents & libc::POLLHUP != 0 {
        return ExitCode::FAILURE;
    }
    // Single-threaded here, so mutating the environment is sound.
    unsafe { std::env::set_var(pam_race::NESTED_ENV, "1") };

    let r = catch_unwind(AssertUnwindSafe(|| authenticate(&setup, &mut ctx)))
        .unwrap_or(Err(PamError::SYSTEM_ERR));
    match wire::send(sock, &proto::encode_done(r)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

fn authenticate(setup: &proto::Setup, ctx: &mut Ctx) -> PamResult {
    let conv = pam_conv {
        conv: Some(converse),
        appdata_ptr: (ctx as *mut Ctx).cast(),
    };
    let mut h: *mut pam_handle_t = ptr::null_mut();
    let confdir = setup
        .confdir
        .as_ref()
        .map_or(ptr::null(), |c| c.as_cstr().as_ptr());
    let started = pam_result(unsafe {
        pam_start_confdir(
            setup.service.as_cstr().as_ptr(),
            setup.user.as_cstr().as_ptr(),
            &conv,
            confdir,
            &mut h,
        )
    });
    if let Err(e) = started {
        log(&format!("pam_start({}): {e}", setup.service));
        return started;
    }
    let r = set_items(h, setup)
        .and_then(|()| pam_result(unsafe { pam_authenticate(h, setup.flags.raw()) }))
        .and_then(|()| same_user(h, &setup.user));
    unsafe { pam_end(h, pam_code(r)) };
    r
}

/// The PAM items the sub-stack would have seen in the host. Missing one
/// could change a module's decision (pam_access, pam_securetty), so failing
/// to set it fails the attempt.
fn set_items(h: *mut pam_handle_t, setup: &proto::Setup) -> PamResult {
    for (item, v) in [
        (PAM_TTY, &setup.tty),
        (PAM_RHOST, &setup.rhost),
        (PAM_RUSER, &setup.ruser),
    ] {
        if let Some(v) = v {
            pam_result(unsafe { pam_set_item(h, item, v.as_cstr().as_ptr().cast()) }).inspect_err(
                |e| {
                    log(&format!("pam_set_item({item}): {e}"));
                },
            )?;
        }
    }
    Ok(())
}

/// Success only counts for the user the module asked about: the outer
/// handle keeps that user, so a sub-stack that switched PAM_USER (user
/// mapping, canonicalization) authenticated someone else.
fn same_user(h: *mut pam_handle_t, expected: &UserName) -> PamResult {
    let mut p: *const c_void = ptr::null();
    pam_result(unsafe { pam_get_item(h, PAM_USER, &mut p) })?;
    let user = (!p.is_null())
        .then(|| UserName::parse(unsafe { CStr::from_ptr(p.cast()) }.to_bytes()))
        .flatten();
    if user.as_ref() == Some(expected) {
        return Ok(());
    }
    log(&format!(
        "sub-stack switched PAM_USER from {expected} to {}; not accepting its success",
        user.as_ref().map_or("(none)".into(), |u| u.to_string())
    ));
    Err(PamError::AUTH_ERR)
}

unsafe extern "C" fn converse(
    n: c_int,
    msg: *mut *const pam_message,
    resp: *mut *mut pam_response,
    appdata: *mut c_void,
) -> c_int {
    let r = catch_unwind(AssertUnwindSafe(|| unsafe {
        if resp.is_null() {
            return Err(PamError::CONV_ERR);
        }
        *resp = ptr::null_mut();
        let msgs = parse_messages(n, msg).ok_or(PamError::CONV_ERR)?;
        let answers = relay(&msgs, &mut *appdata.cast::<Ctx>())?;
        *resp = into_pam_responses(answers.as_ref(), msgs.len())?;
        Ok(())
    }));
    pam_code(r.unwrap_or(Err(PamError::CONV_ERR)))
}

/// Linux-PAM calling convention: `msg[i]` points at message i.
unsafe fn parse_messages(n: c_int, msg: *mut *const pam_message) -> Option<Messages> {
    let n = usize::try_from(n).ok().filter(|n| *n <= PAM_MAX_NUM_MSG)?;
    if msg.is_null() {
        return None;
    }
    let v = (0..n)
        .map(|i| {
            let m = unsafe { (*msg.add(i)).as_ref()? };
            let style = Style::parse(m.msg_style)?; // e.g. binary prompts: unsupported
            let text = if m.msg.is_null() {
                c""
            } else {
                unsafe { CStr::from_ptr(m.msg) }
            };
            Some(Message {
                style,
                text: Text::truncating(text),
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Messages::parse(v)
}

/// Forward one conversation call to the module; for prompts, wait for the
/// user's answers.
fn relay(msgs: &Messages, ctx: &mut Ctx) -> Result<Option<Responses>, PamError> {
    wire::send(ctx.sock, &proto::encode_conv(msgs)).map_err(|_| PamError::CONV_ERR)?;
    if !msgs.is_prompt() {
        return Ok(None);
    }
    let r = match wire::recv(ctx.sock, &mut ctx.buf) {
        Ok(Some(pkt)) => proto::decode_reply(pkt, msgs).map_err(|e| {
            log(&e.to_string());
            PamError::CONV_ERR
        }),
        _ => Err(PamError::CONV_ERR),
    };
    unsafe { libc::explicit_bzero(ctx.buf.as_mut_ptr().cast(), ctx.buf.len()) };
    r.map(Some)
}

/// libpam takes ownership and frees the array and every resp with free(3).
fn into_pam_responses(
    answers: Option<&Responses>,
    n: usize,
) -> Result<*mut pam_response, PamError> {
    let arr = unsafe { libc::calloc(n, size_of::<pam_response>()) }.cast::<pam_response>();
    if arr.is_null() {
        return Err(PamError::BUF_ERR);
    }
    for (i, s) in answers.map_or(&[][..], |r| r.as_slice()).iter().enumerate() {
        let Some(s) = s else { continue };
        let b = s.as_bytes();
        let p = unsafe { libc::malloc(b.len() + 1) }.cast::<u8>();
        if p.is_null() {
            unsafe { free_pam_responses(arr, n) };
            return Err(PamError::BUF_ERR);
        }
        unsafe {
            ptr::copy_nonoverlapping(b.as_ptr(), p, b.len());
            *p.add(b.len()) = 0;
            (*arr.add(i)).resp = p.cast();
        }
    }
    Ok(arr)
}

unsafe fn free_pam_responses(arr: *mut pam_response, n: usize) {
    for i in 0..n {
        let r = unsafe { (*arr.add(i)).resp };
        if !r.is_null() {
            unsafe {
                libc::explicit_bzero(r.cast(), libc::strlen(r));
                libc::free(r.cast());
            }
        }
    }
    unsafe { libc::free(arr.cast()) };
}
