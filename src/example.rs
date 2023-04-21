use std::{io::Read, os::unix::net::UnixListener, path::Path, u32};

use clap::Parser;
use log::{debug, error, info};
use lumper::VMM;

#[derive(Parser, Debug)]
#[clap(version = "0.1", author = "Polytech Montpellier - DevOps")]
struct VMMOpts {
    /// Linux kernel path
    #[clap(short, long)]
    kernel: String,

    /// Initramfs path
    #[clap(short, long)]
    initramfs: Option<String>,

    /// Number of virtual CPUs assigned to the guest
    #[clap(short, long, default_value = "1")]
    cpus: u8,

    /// Memory amount (in MBytes) assigned to the guest
    #[clap(short, long, default_value = "512")]
    memory: u32,

    /// A level of verbosity, and can be used multiple times
    #[clap(short, long, action=clap::ArgAction::Count )]
    verbose: u8,

    /// Stdout console file path
    #[clap(long)]
    console: Option<String>,

    /// Interface name
    #[clap(long)]
    net: Option<String>,

    /// Guest IP address with CIDR
    #[clap(long)]
    ip: Option<String>,

    // Default gateway
    #[clap(long)]
    gateway: Option<String>,

    /// no-console
    #[clap(long)]
    no_console: bool,

    /// Unix socket path
    #[clap(long)]
    socket: Option<String>,
}

#[derive(Debug)]
pub enum Error {
    VmmNew(lumper::Error),

    VmmConfigure(lumper::Error),

    VmmRun(lumper::Error),
}

fn main() -> Result<(), Error> {
    env_logger::init();

    if std::env::var("RUST_LOG").is_err() {
        // If not, set it to "info" by default
        std::env::set_var("RUST_LOG", "info");
    }

    let opts: VMMOpts = VMMOpts::parse();

    if opts.console.is_some() && opts.socket.is_some() {
        error!("You can't use --console and --socket at the same time");
        return Ok(());
    }

    if let Some(socket) = opts.socket.as_ref() {
        let path = Path::new(socket.as_str());
        let unix_listener = UnixListener::bind(path).unwrap();

        std::thread::spawn(move || {
            // read from socket
            let (mut stream, _) = unix_listener.accept().unwrap();
            let mut buffer = [0; 1024];
            loop {
                let n = stream.read(&mut buffer).unwrap();
                if n == 0 {
                    break;
                }
                let s = String::from_utf8_lossy(&buffer[0..n]).to_string();
                info!("{}", s);
            }
        });
    }

    // Create a new VMM
    let mut vmm = VMM::new().map_err(Error::VmmNew)?;

    debug!("Configure VMM with {:?}", opts);

    // Configure the VMM:
    // * Number of virtual CPUs
    // * Memory size (in MB)
    // * Path to a Linux kernel
    // * Optional path to console file
    vmm.configure(
        opts.cpus,
        opts.memory,
        &opts.kernel,
        opts.console,
        opts.initramfs,
        opts.net,
        opts.socket,
        opts.no_console,
        opts.ip,
        opts.gateway,
    )
    .map_err(Error::VmmConfigure)?;

    info!("Starting VMM ...");

    // Run the VMM
    vmm.run(opts.no_console).map_err(Error::VmmRun)?;

    Ok(())
}
