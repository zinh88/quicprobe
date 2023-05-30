use aya::programs::UProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<i32>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut ret_bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/quicprobe"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut ret_bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/quicprobe"
    ))?;
    if let Err(e) = BpfLogger::init(&mut ret_bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut UProbe = ret_bpf.program_mut("quicprobe").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("_ZN6quiche10Connection4recv17h9f70c393ef1c57d0E"), 0, "/home/zain/probes/quiche/target/debug/quiche-client", opt.pid)?;

    
    let program2: &mut UProbe = ret_bpf.program_mut("testentry").unwrap().try_into()?;
    program2.load()?;
    program2.attach(Some("_ZN6quiche10Connection4recv17h9f70c393ef1c57d0E"), 0, "/home/zain/probes/quiche/target/debug/quiche-client", opt.pid)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
