//! Hand-written Linux-PAM bindings: only what this crate needs.
//! Values verified against `<security/_pam_types.h>` (Linux-PAM 1.7).

#![allow(non_camel_case_types)]

use libc::{c_char, c_int, c_void};

#[repr(C)]
pub struct pam_handle_t {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct pam_message {
    pub msg_style: c_int,
    pub msg: *const c_char,
}

#[repr(C)]
pub struct pam_response {
    pub resp: *mut c_char,
    pub resp_retcode: c_int,
}

pub type ConvFn = unsafe extern "C" fn(
    num_msg: c_int,
    msg: *mut *const pam_message,
    resp: *mut *mut pam_response,
    appdata_ptr: *mut c_void,
) -> c_int;

#[repr(C)]
pub struct pam_conv {
    pub conv: Option<ConvFn>,
    pub appdata_ptr: *mut c_void,
}

// Return codes.
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_SERVICE_ERR: c_int = 3;
pub const PAM_SYSTEM_ERR: c_int = 4;
pub const PAM_BUF_ERR: c_int = 5;
pub const PAM_AUTH_ERR: c_int = 7;
pub const PAM_CONV_ERR: c_int = 19;

// Flags.
pub const PAM_SILENT: c_int = 0x8000;
pub const PAM_DISALLOW_NULL_AUTHTOK: c_int = 0x0001;

// Items.
pub const PAM_SERVICE: c_int = 1;
pub const PAM_USER: c_int = 2;
pub const PAM_TTY: c_int = 3;
pub const PAM_RHOST: c_int = 4;
pub const PAM_CONV: c_int = 5;
pub const PAM_RUSER: c_int = 8;

// Message styles.
pub const PAM_PROMPT_ECHO_OFF: c_int = 1;
pub const PAM_PROMPT_ECHO_ON: c_int = 2;
pub const PAM_ERROR_MSG: c_int = 3;
pub const PAM_TEXT_INFO: c_int = 4;

pub const PAM_MAX_NUM_MSG: usize = 32;

#[link(name = "pam")]
unsafe extern "C" {
    pub fn pam_start_confdir(
        service: *const c_char,
        user: *const c_char,
        conv: *const pam_conv,
        confdir: *const c_char,
        pamh: *mut *mut pam_handle_t,
    ) -> c_int;
    pub fn pam_end(pamh: *mut pam_handle_t, status: c_int) -> c_int;
    pub fn pam_authenticate(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    pub fn pam_get_user(
        pamh: *mut pam_handle_t,
        user: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
    pub fn pam_get_item(pamh: *const pam_handle_t, item: c_int, out: *mut *const c_void) -> c_int;
    pub fn pam_set_item(pamh: *mut pam_handle_t, item: c_int, value: *const c_void) -> c_int;
}
