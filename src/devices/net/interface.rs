use std::{
    io::{Read, Write},
    os::fd::AsRawFd,
};

use super::Result;

/// Trait for virtio network interfaces.
pub trait Interface: Read + Write + AsRawFd + Send + Sync {
    /// Initializes the virtio network interface.
    ///
    /// # Arguments
    ///
    /// * `virtio_flags` - virtio feature flags. <https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-1970003>
    /// * `virtio_header_size` - size of the virtio header.
    fn activate(&self, virtio_flags: u64, virtio_header_size: usize) -> Result<()>;

    /// Opens or creates an interface with the given name on the host.
    fn open_named(if_name: &str) -> Result<Self>
    where
        Self: Sized;
}
