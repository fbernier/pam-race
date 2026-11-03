//! `pam_race`: run several PAM services concurrently; the first to succeed wins.
//!
//! ```text
//! auth  required  pam_race.so  [debug] [settle=MS] [helper=PATH] [confdir=DIR] SERVICE...
//! ```
//!
//! Layout: a functional core ([`types`], [`config`], [`proto`], [`arbiter`])
//! that parses every boundary into types and decides the race without I/O,
//! inside an imperative shell (this file's FFI entry points, `race`,
//! [`spawn`], `tty`, [`wire`]). See README.md for the design.

pub mod arbiter;
pub mod config;
pub mod ffi;
pub mod proto;
pub mod spawn;
pub mod types;
pub mod wire;

mod race;
mod tty;

use std::ffi::{CStr, CString, c_char, c_int};
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};

use config::Config;
use ffi::*;
use types::*;

/// Set by the helper before it starts a sub-stack. A sub-stack that loads
/// pam_race again would otherwise fork helpers without bound.
pub const NESTED_ENV: &str = "PAM_RACE_NESTED";

/// syslog(3) in pam_syslog's format. Usable from any thread, unlike
/// pam_syslog, which would read the handle concurrently with the host.
pub(crate) struct Log {
    prefix: CString,
    debug: bool,
}

impl Log {
    fn new(service: &str, debug: bool) -> Log {
        let prefix = format!("pam_race({service}:auth):").replace('\0', "?");
        Log {
            prefix: CString::new(prefix).expect("NULs replaced"),
            debug,
        }
    }
    fn write(&self, prio: c_int, args: fmt::Arguments<'_>) {
        let msg = CString::new(args.to_string().replace('\0', "?")).expect("NULs replaced");
        unsafe {
            libc::syslog(
                libc::LOG_AUTHPRIV | prio,
                c"%s %s".as_ptr(),
                self.prefix.as_ptr(),
                msg.as_ptr(),
            )
        };
    }
    pub fn err(&self, args: fmt::Arguments<'_>) {
        self.write(libc::LOG_ERR, args)
    }
    pub fn notice(&self, args: fmt::Arguments<'_>) {
        self.write(libc::LOG_NOTICE, args)
    }
    pub fn debug(&self, args: fmt::Arguments<'_>) {
        if self.debug {
            self.write(libc::LOG_DEBUG, args)
        }
    }
}

/// A string item of the handle, borrowed: valid until the item is changed.
unsafe fn item<'a>(pamh: *mut pam_handle_t, item: c_int) -> Option<&'a CStr> {
    let mut p: *const libc::c_void = std::ptr::null();
    if unsafe { pam_get_item(pamh, item, &mut p) } != PAM_SUCCESS || p.is_null() {
        return None;
    }
    Some(unsafe { CStr::from_ptr(p.cast()) })
}

/// PAM module entry point.
///
/// # Safety
/// Called by libpam with a live handle and `argc` valid C strings in `argv`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_handle_t,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // Unwinding into C is undefined behaviour; a panic is a module error.
    let r = catch_unwind(AssertUnwindSafe(|| unsafe {
        authenticate(pamh, flags, argc, argv)
    }));
    pam_code(r.unwrap_or(Err(PamError::SERVICE_ERR)))
}

unsafe fn authenticate(
    pamh: *mut pam_handle_t,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> PamResult {
    let service = unsafe { item(pamh, PAM_SERVICE) }
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let args =
        (0..argc.max(0) as usize).map(|i| unsafe { CStr::from_ptr(*argv.add(i)) }.to_bytes());
    let cfg = Config::parse(args).map_err(|e| {
        Log::new(&service, false).err(format_args!("{e}"));
        PamError::SERVICE_ERR
    })?;
    let log = Log::new(&service, cfg.debug);
    if std::env::var_os(NESTED_ENV).is_some() {
        log.err(format_args!("refusing to run inside a pam_race sub-stack"));
        return Err(PamError::SERVICE_ERR);
    }
    if cfg
        .services
        .iter()
        .any(|s| s.as_cstr().to_bytes() == service.as_bytes())
    {
        log.err(format_args!("service {service} cannot race itself"));
        return Err(PamError::SERVICE_ERR);
    }
    let Some(conv) = (unsafe { race::HostConv::of(pamh) }) else {
        log.err(format_args!(
            "application provided no conversation function"
        ));
        return Err(PamError::CONV_ERR);
    };

    let mut user: *const c_char = std::ptr::null();
    pam_result(unsafe { pam_get_user(pamh, &mut user, std::ptr::null()) })?;
    let user = (!user.is_null())
        .then(|| UserName::parse(unsafe { CStr::from_ptr(user) }.to_bytes()))
        .flatten()
        .ok_or(PamError::SERVICE_ERR)?;
    // Every sub-stack must see these as the host set them (they can change a
    // module's decision), so one that cannot be forwarded fails the race.
    let forward = |which: c_int, name: &str| {
        unsafe { item(pamh, which) }
            .map(|v| {
                ItemValue::parse(v.to_bytes()).ok_or_else(|| {
                    log.err(format_args!("{name} is too long to forward"));
                    PamError::SERVICE_ERR
                })
            })
            .transpose()
    };
    let items = race::Items {
        tty: forward(PAM_TTY, "PAM_TTY")?,
        rhost: forward(PAM_RHOST, "PAM_RHOST")?,
        ruser: forward(PAM_RUSER, "PAM_RUSER")?,
    };
    race::run(conv, &cfg, &log, AuthFlags::from_raw(flags), user, items)
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(
    _: *mut pam_handle_t,
    _: c_int,
    _: c_int,
    _: *const *const c_char,
) -> c_int {
    // Sub-stacks only run their auth phase; there are no credentials to set.
    PAM_SUCCESS
}
