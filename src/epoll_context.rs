// SPDX-License-Identifier: Apache-2.0

extern crate epoll;

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;

/// Maximum number of events that can be stored in the buffer, this may need to be moved elsewhere.
pub(crate) const EPOLL_EVENTS_LEN: usize = 10;

/// This is a simple wrapper around epoll to make adding new file descriptors easier.
pub struct EpollContext {
    raw_fd: RawFd,
}

impl EpollContext {
    /// Create a new epoll context (epoll file descriptor)
    pub fn new() -> result::Result<EpollContext, io::Error> {
        let raw_fd = epoll::create(true)?;
        Ok(EpollContext { raw_fd })
    }

    pub fn add_stdin(&self) -> result::Result<(), io::Error> {
        epoll::ctl(
            self.raw_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            libc::STDIN_FILENO,
            epoll::Event::new(epoll::Events::EPOLLIN, libc::STDIN_FILENO as u64),
        )?;

        Ok(())
    }
    pub fn add_fd(&self, fd: RawFd) -> result::Result<(), io::Error> {
        epoll::ctl(
            self.raw_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd,
            epoll::Event::new(epoll::Events::EPOLLIN, fd as u64),
        )?;

        Ok(())
    }
}

impl AsRawFd for EpollContext {
    /// Get the raw file descriptor of the epoll context
    fn as_raw_fd(&self) -> RawFd {
        self.raw_fd
    }
}
