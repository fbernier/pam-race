//! Packet transport over the helper socket.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

/// Send one packet. `MSG_NOSIGNAL`: a dead peer must surface as `EPIPE`, not
/// as a SIGPIPE delivered to the host application.
pub fn send(fd: BorrowedFd<'_>, pkt: &[u8]) -> io::Result<()> {
    loop {
        let n = unsafe {
            libc::send(
                fd.as_raw_fd(),
                pkt.as_ptr().cast(),
                pkt.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if n >= 0 {
            // SOCK_SEQPACKET sends are all-or-nothing.
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// Receive one packet into `buf`, waiting for it; `Ok(None)` on orderly EOF.
pub fn recv<'b>(fd: BorrowedFd<'_>, buf: &'b mut [u8]) -> io::Result<Option<&'b [u8]>> {
    recv_flags(fd, buf, 0)
}

/// [`recv`] without waiting: `WouldBlock` if no packet is queued.
pub fn try_recv<'b>(fd: BorrowedFd<'_>, buf: &'b mut [u8]) -> io::Result<Option<&'b [u8]>> {
    recv_flags(fd, buf, libc::MSG_DONTWAIT)
}

fn recv_flags<'b>(
    fd: BorrowedFd<'_>,
    buf: &'b mut [u8],
    flags: libc::c_int,
) -> io::Result<Option<&'b [u8]>> {
    loop {
        // MSG_TRUNC makes recv return the real packet size, so an oversized
        // packet is detected instead of silently cut.
        let n = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_TRUNC | flags,
            )
        };
        match n {
            0 => return Ok(None),
            n if n > 0 => {
                let n = n as usize;
                if n > buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "oversized packet",
                    ));
                }
                return Ok(Some(&buf[..n]));
            }
            _ => {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
        }
    }
}
