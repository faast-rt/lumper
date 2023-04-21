// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Result, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

pub(crate) mod net;
pub(crate) mod serial;

pub struct Writer {
    unix_stream: Arc<Mutex<UnixStream>>,
}

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let _ = &self.unix_stream.lock().unwrap().write(buf).unwrap();

        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Read for Writer {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.unix_stream.lock().unwrap().read(buf)
    }
}

impl Writer {
    pub fn new(unix_stream: Arc<Mutex<UnixStream>>) -> Self {
        Writer { unix_stream }
    }
}

impl AsRawFd for Writer {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.unix_stream.lock().unwrap().as_raw_fd()
    }
}
