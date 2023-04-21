// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#![cfg(target_arch = "x86_64")]

extern crate libc;

extern crate linux_loader;
extern crate vm_memory;
extern crate vm_superio;

use std::any::Any;
use std::fs::File;
use std::io::{stdout, Read};
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::prelude::RawFd;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::{io, path::PathBuf};

use cidr::IpInet;
use devices::net::tap::Tap;
use devices::net::VirtioNet;
use devices::Writer;
use kvm_bindings::{kvm_userspace_memory_region, KVM_MAX_CPUID_ENTRIES};
use kvm_ioctls::{Kvm, VmFd};
use linux_loader::loader::{self, KernelLoaderResult};
use vm_device::device_manager::IoManager;
use vm_device::resources::Resource;
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::rand;
use vmm_sys_util::terminal::Terminal;
mod cpu;
use cpu::{cpuid, mptable, Vcpu};
pub mod devices;
use devices::serial::LumperSerial;

mod epoll_context;
use epoll_context::{EpollContext, EPOLL_EVENTS_LEN};
mod kernel;

const CMDLINE_MAX_SIZE: usize = 4096;

#[derive(Debug)]

/// VMM errors.
pub enum Error {
    /// Failed to write boot parameters to guest memory.
    BootConfigure(linux_loader::configurator::Error),
    /// Error configuring the kernel command line.
    Cmdline(linux_loader::cmdline::Error),
    /// Failed to load kernel.
    KernelLoad(loader::Error),
    /// Failed to load initrd.
    InitramfsLoad,
    /// Invalid E820 configuration.
    E820Configuration,
    /// Highmem start address is past the guest memory end.
    HimemStartPastMemEnd,
    /// I/O error.
    IO(io::Error),
    /// Error issuing an ioctl to KVM.
    KvmIoctl(kvm_ioctls::Error),
    /// vCPU errors.
    Vcpu(cpu::Error),
    /// Memory error.
    Memory(vm_memory::Error),
    /// Serial creation error
    SerialCreation(io::Error),
    /// IRQ registration error
    IrqRegister(io::Error),
    /// epoll creation error
    EpollError(io::Error),
    /// STDIN read error
    StdinRead(kvm_ioctls::Error),
    /// STDIN write error
    StdinWrite(vm_superio::serial::Error<io::Error>),
    /// Terminal configuration error
    TerminalConfigure(kvm_ioctls::Error),
    /// Console configuration error
    ConsoleError(io::Error),
    /// IntoString error
    IntoStringError(std::ffi::IntoStringError),
    /// Error writing to the guest memory.
    GuestMemory(vm_memory::guest_memory::Error),
    /// Error related to the virtio-net device.
    VirtioNet(devices::net::VirtioNetError),
    /// Error related to IOManager.
    IoManager(vm_device::device_manager::Error),
    /// Access thread handler error
    AccessThreadHandlerError,
    /// Join thread error
    JoinThreadError(Box<dyn Any + Send>),
    /// Writer configuration error
    WriterError(io::Error),
    /// Not a valid CIDR address
    InvalidCIDRAddress(cidr::errors::NetworkParseError),
    /// Not a valid IP address
    InvalidIPAddress(std::net::AddrParseError),
}

/// Dedicated [`Result`](https://doc.rust-lang.org/std/result/) type.
pub type Result<T> = std::result::Result<T, Error>;

pub struct VMM {
    vm_fd: VmFd,
    kvm: Kvm,
    guest_memory: GuestMemoryMmap,
    vcpus: Vec<Vcpu>,

    serial: Arc<Mutex<LumperSerial>>,
    socket_stream: Option<Arc<Mutex<UnixStream>>>,
    virtio_manager: Arc<Mutex<IoManager>>,
    virtio_net: Option<Arc<Mutex<VirtioNet<Arc<GuestMemoryMmap>, Tap>>>>,

    epoll: EpollContext,

    cmdline: linux_loader::cmdline::Cmdline,
}

impl VMM {
    /// Create a new VMM.
    pub fn new() -> Result<Self> {
        // Open /dev/kvm and get a file descriptor to it.
        let kvm = Kvm::new().map_err(Error::KvmIoctl)?;

        // Create a KVM VM object.
        // KVM returns a file descriptor to the VM object.
        let vm_fd = kvm.create_vm().map_err(Error::KvmIoctl)?;

        let epoll = EpollContext::new().map_err(Error::EpollError)?;
        epoll.add_stdin().map_err(Error::EpollError)?;

        let vmm = VMM {
            vm_fd,
            kvm,
            guest_memory: GuestMemoryMmap::default(),
            vcpus: vec![],
            serial: Arc::new(Mutex::new(
                LumperSerial::new(Box::new(stdout())).map_err(Error::SerialCreation)?,
            )),
            socket_stream: None,
            virtio_net: None,
            virtio_manager: Arc::new(Mutex::new(IoManager::new())),
            epoll,
            cmdline: linux_loader::cmdline::Cmdline::new(CMDLINE_MAX_SIZE)
                .map_err(Error::Cmdline)?,
        };

        Ok(vmm)
    }

    pub fn configure_memory(&mut self, mem_size_mb: u32) -> Result<()> {
        // Convert memory size from MBytes to bytes.
        let mem_size = ((mem_size_mb as u64) << 20) as usize;

        // Create one single memory region, from zero to mem_size.
        let mem_regions = vec![(GuestAddress(0), mem_size)];

        // Allocate the guest memory from the memory region.
        let guest_memory = GuestMemoryMmap::from_ranges(&mem_regions).map_err(Error::Memory)?;

        // For each memory region in guest_memory:
        // 1. Create a KVM memory region mapping the memory region guest physical address to the host virtual address.
        // 2. Register the KVM memory region with KVM. EPTs are created then.
        for (index, region) in guest_memory.iter().enumerate() {
            let kvm_memory_region = kvm_userspace_memory_region {
                slot: index as u32,
                guest_phys_addr: region.start_addr().raw_value(),
                memory_size: region.len() as u64,
                // It's safe to unwrap because the guest address is valid.
                userspace_addr: guest_memory.get_host_address(region.start_addr()).unwrap() as u64,
                flags: 0,
            };

            // Register the KVM memory region with KVM.
            unsafe { self.vm_fd.set_user_memory_region(kvm_memory_region) }
                .map_err(Error::KvmIoctl)?;
        }

        self.guest_memory = guest_memory;

        Ok(())
    }

    pub fn load_default_cmdline(&mut self) -> Result<()> {
        self.cmdline
            .insert_str(kernel::DEFAULT_CMDLINE)
            .map_err(Error::Cmdline)
    }
    // configure the virtio-net device
    pub fn configure_net(
        &mut self,
        interface: Option<String>,
        ip: Option<String>,
        gateway: Option<String>,
    ) -> Result<()> {
        let if_name = match interface {
            Some(if_name) => if_name,
            None => return Ok(()),
        };

        // Temporary hardcoded address, see allocator PR
        let virtio_address = GuestAddress(0xd0000000);

        let irq_fd = EventFd::new(libc::EFD_NONBLOCK).map_err(Error::IrqRegister)?;

        let virtio_net = VirtioNet::new(
            Arc::new(self.guest_memory.clone()),
            irq_fd,
            if_name.as_str(),
        )
        .map_err(Error::VirtioNet)?;

        self.epoll
            .add_fd(virtio_net.as_raw_fd())
            .map_err(Error::EpollError)?;
        let mut io_manager = self.virtio_manager.lock().unwrap();

        self.virtio_net = Some(Arc::new(Mutex::new(virtio_net)));

        io_manager
            .register_mmio_resources(
                // It's safe to unwrap because the virtio-net was just assigned
                self.virtio_net.as_ref().unwrap().clone(),
                &[
                    Resource::GuestAddressRange {
                        base: virtio_address.raw_value(),
                        size: 0x1000,
                    },
                    Resource::LegacyIrq(5),
                ],
            )
            .map_err(Error::IoManager)?;

        // Add the virtio-net device to the cmdline.
        self.cmdline
            .add_virtio_mmio_device(0x1000, virtio_address, 5, None)
            .map_err(Error::Cmdline)?;

        // Parse the CIDR string, and find the IP adrress and netmask.
        if let Some(ip) = ip {
            let cidr = ip.parse::<IpInet>().map_err(Error::InvalidCIDRAddress)?;
            let ip_addr = cidr.address().to_string();
            let netmask = cidr.mask().to_string();
            println!("ip: {}, netmask: {}", ip_addr, netmask);
            if let Some(gateway) = gateway {
                let gateway = gateway
                    .parse::<Ipv4Addr>()
                    .map_err(Error::InvalidIPAddress)?;
                self.cmdline
                    .insert_str(format!("ip={}::{}:{}::eth0:off", ip_addr, gateway, netmask))
                    .map_err(Error::Cmdline)?;
            } else {
                self.cmdline
                    .insert_str(format!("ip={}:::{}::eth0:off", ip_addr, netmask))
                    .map_err(Error::Cmdline)?;
            }
        }

        Ok(())
    }

    pub fn configure_io(&mut self) -> Result<()> {
        // First, create the irqchip.
        // On `x86_64`, this _must_ be created _before_ the vCPUs.
        // It sets up the virtual IOAPIC, virtual PIC, and sets up the future vCPUs for local APIC.
        // When in doubt, look in the kernel for `KVM_CREATE_IRQCHIP`.
        // https://elixir.bootlin.com/linux/latest/source/arch/x86/kvm/x86.c
        self.vm_fd.create_irq_chip().map_err(Error::KvmIoctl)?;

        self.vm_fd
            .register_irqfd(
                &self
                    .serial
                    .lock()
                    .unwrap()
                    .eventfd()
                    .map_err(Error::IrqRegister)?,
                4,
            )
            .map_err(Error::KvmIoctl)?;

        if let Some(virtio_net) = self.virtio_net.as_ref() {
            self.vm_fd
                .register_irqfd(&virtio_net.lock().unwrap().guest_irq_fd, 5)
                .map_err(Error::KvmIoctl)?;
        }
        Ok(())
    }

    pub fn configure_writer(&mut self, writer: Option<Writer>) -> Result<()> {
        if let Some(writer) = writer {
            let mut serial = self.serial.lock().unwrap();
            *serial = LumperSerial::new(Box::new(writer)).map_err(Error::WriterError)?;
        }
        Ok(())
    }

    pub fn configure_console(
        &mut self,
        console_path: Option<String>,
        socket_path: Option<String>,
        no_console: bool,
    ) -> Result<()> {
        if let Some(console_path) = console_path {
            // We create the file if it does not exist, else we open
            let file = File::create(&console_path).map_err(Error::ConsoleError)?;

            let mut serial = self.serial.lock().unwrap();
            *serial = LumperSerial::new(Box::new(file)).map_err(Error::SerialCreation)?;
        }

        if let Some(socket_path) = socket_path {
            let unix_stream = Arc::new(Mutex::new(UnixStream::connect(socket_path).unwrap()));
            self.socket_stream = Some(unix_stream.clone());
            self.epoll
                .add_fd(unix_stream.lock().unwrap().as_raw_fd())
                .unwrap();

            let writer = Writer::new(unix_stream);
            let mut serial = self.serial.lock().unwrap();

            *serial = LumperSerial::new(Box::new(writer)).map_err(Error::SerialCreation)?;
        }

        if !no_console {
            self.cmdline
                .insert_str("console=ttyS0")
                .map_err(Error::Cmdline)?;
        }

        Ok(())
    }

    pub fn configure_vcpus(
        &mut self,
        num_vcpus: u8,
        kernel_load: KernelLoaderResult,
    ) -> Result<()> {
        mptable::setup_mptable(&self.guest_memory, num_vcpus)
            .map_err(|e| Error::Vcpu(cpu::Error::Mptable(e)))?;

        let base_cpuid = self
            .kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .map_err(Error::KvmIoctl)?;

        for index in 0..num_vcpus {
            let vcpu = Vcpu::new(
                &self.vm_fd,
                index.into(),
                Arc::clone(&self.serial),
                self.virtio_manager.clone(),
            )
            .map_err(Error::Vcpu)?;

            // Set CPUID.
            let mut vcpu_cpuid = base_cpuid.clone();
            cpuid::filter_cpuid(
                &self.kvm,
                index as usize,
                num_vcpus as usize,
                &mut vcpu_cpuid,
            );
            vcpu.configure_cpuid(&vcpu_cpuid).map_err(Error::Vcpu)?;

            // Configure MSRs (model specific registers).
            vcpu.configure_msrs().map_err(Error::Vcpu)?;

            // Configure regs, sregs and fpu.
            vcpu.configure_regs(kernel_load.kernel_load)
                .map_err(Error::Vcpu)?;
            vcpu.configure_sregs(&self.guest_memory)
                .map_err(Error::Vcpu)?;
            vcpu.configure_fpu().map_err(Error::Vcpu)?;

            // Configure LAPICs.
            vcpu.configure_lapic().map_err(Error::Vcpu)?;

            self.vcpus.push(vcpu);
        }

        Ok(())
    }

    // Run all virtual CPUs.
    pub fn run(&mut self, no_console: bool) -> Result<()> {
        let mut unix_socket_name = String::from("/tmp/vmm.sock");
        while Path::new(&unix_socket_name).exists() {
            let rng = rand::rand_alphanumerics(8);
            unix_socket_name = format!("/tmp/vmm-{}.sock", rng.to_str().unwrap());
        }

        let mut handlers: Vec<thread::JoinHandle<_>> = Vec::new();
        let listener = UnixListener::bind(unix_socket_name.as_str()).unwrap();
        let total_cpus = self.vcpus.len();

        for mut vcpu in self.vcpus.drain(..) {
            let socket_name = unix_socket_name.clone();
            let handler = thread::Builder::new().spawn(move || {
                vcpu.run(socket_name.clone());
            });

            match handler {
                Ok(handler) => handlers.push(handler),
                Err(_) => {
                    println!("Failed to start vCPU");
                    return Err(Error::AccessThreadHandlerError);
                }
            }
        }

        let mut connections: Vec<_> = Vec::new();

        while connections.len() < total_cpus {
            let connection = listener.accept().unwrap().0;
            self.epoll.add_fd(connection.as_raw_fd()).unwrap();
            connections.push(connection);
        }

        self.epoll.add_fd(listener.as_raw_fd()).unwrap();

        let stdin_lock = if !no_console {
            let stdin = io::stdin();
            let stdin_lock = stdin.lock();
            stdin_lock
                .set_raw_mode()
                .map_err(Error::TerminalConfigure)?;
            Some(stdin_lock)
        } else {
            None
        };

        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];
        let epoll_fd = self.epoll.as_raw_fd();
        let interface_fd = match self.virtio_net.as_ref() {
            Some(virtio_net) => Some(virtio_net.lock().unwrap().interface.as_raw_fd()),
            None => None,
        };

        let socket_fd = match self.socket_stream.as_ref() {
            Some(socket) => Some(socket.lock().unwrap().as_raw_fd()),
            None => None,
        };
        // Let's start the STDIN/Network interface polling thread.
        loop {
            let num_events = match epoll::wait(epoll_fd, -1, &mut events[..]) {
                Ok(num_events) => num_events,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    } else {
                        return Err(Error::EpollError(e));
                    }
                }
            };

            for event in events.iter().take(num_events) {
                let event_data = event.data as RawFd;

                if event_data == libc::STDIN_FILENO && stdin_lock.as_ref().is_some() {
                    let mut out = [0u8; 64];

                    let count = stdin_lock
                        .as_ref()
                        .unwrap()
                        .read_raw(&mut out)
                        .map_err(Error::StdinRead)?;

                    self.serial
                        .lock()
                        .unwrap()
                        .serial
                        .enqueue_raw_bytes(&out[..count])
                        .map_err(Error::StdinWrite)?;
                }

                if socket_fd == Some(event_data) {
                    let mut out = [0u8; 512];

                    let count = self
                        .socket_stream
                        .as_ref()
                        .unwrap()
                        .lock()
                        .unwrap()
                        .read(&mut out)
                        .unwrap();

                    for c in out.iter().take(count) {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        let mut buf = [0u8; 1];
                        buf[0] = *c;
                        while self
                            .serial
                            .lock()
                            .unwrap()
                            .serial
                            .enqueue_raw_bytes(&buf)
                            .is_err()
                        {}
                    }
                }

                if interface_fd == Some(event_data) {
                    self.virtio_net
                        .as_ref()
                        // Safe because we checked that the virtio_net is Some before the loop.
                        .unwrap()
                        .lock()
                        .unwrap()
                        .process_tap()
                        .map_err(Error::VirtioNet)?;
                }

                if connections.iter().any(|c| c.as_raw_fd() == event_data) {
                    println!("Shutting down");
                    handlers.iter().for_each(|handler| {
                        let thread = handler.thread();
                        std::thread::Thread::unpark(thread);
                    });
                    return Ok(());
                }
            }
        }
    }

    pub fn configure(
        &mut self,
        num_vcpus: u8,
        mem_size_mb: u32,
        kernel_path: &str,
        console: Option<String>,
        initramfs_path: Option<String>,
        if_name: Option<String>,
        socket_path: Option<String>,
        no_console: bool,
        ip: Option<String>,
        gateway: Option<String>,
    ) -> Result<()> {
        self.configure_console(console, socket_path, no_console)?;
        self.configure_memory(mem_size_mb)?;
        self.load_default_cmdline()?;

        self.configure_net(if_name, ip, gateway)?;

        let kernel_load = kernel::kernel_setup(
            &self.guest_memory,
            PathBuf::from(kernel_path),
            initramfs_path,
            &self.cmdline,
        )?;
        self.configure_io()?;
        self.configure_vcpus(num_vcpus, kernel_load)?;

        Ok(())
    }
}
