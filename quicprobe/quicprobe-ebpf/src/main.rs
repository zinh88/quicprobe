#![no_std]
#![no_main]

use aya_bpf::{
    macros::{uretprobe, uprobe, map},
    programs::ProbeContext,
    helpers::bpf_probe_read_user,
    maps::{PerCpuHashMap},
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_buf}, bindings::{BPF_ANY, BPF_F_NO_PREALLOC}
};
use aya_log_ebpf::info;

#[map(name="bufs")]
static mut BUFFER_PTR: PerCpuHashMap<u64, usize> = 
    PerCpuHashMap::<u64, usize>::with_max_entries(1024, BPF_F_NO_PREALLOC);


#[uprobe(name="testentry")]
pub fn testentry(ctx: ProbeContext) -> u32 {
    match try_testentry(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_testentry(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "recv() called by quiche-client");
    let buff_arg: *const &[u8] = ctx.arg(0).ok_or(1u32)?;
    let bytes = unsafe {
        bpf_probe_read_user(buff_arg)
        .map_err(|_| 1u32)?
    };
    info!(&ctx, "Buffer Size: {}, addr: {}", bytes.len(), buff_arg as usize);
    let pid_gid = bpf_get_current_pid_tgid();
    let addr : usize = buff_arg as usize;
    unsafe {
        BUFFER_PTR.insert(&pid_gid, &addr, 0).map_err(|_| 1u32)?
    }
    info!(&ctx, "Inserted address {} into map", addr);
    info!(&ctx, "~~~~~~~~> Pointer to buffer: {}", bytes as *const [u8] as *const u8 as usize);
    Ok(0)
}

#[uretprobe(name="quicprobe")]
pub fn quicprobe(ctx: ProbeContext) -> u32 {
    match try_quicprobe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn read_buffer(ctx: ProbeContext, addr: &usize) -> Result<u32, u32> {
    info!(&ctx, "Obtained pointer: {}", addr); 
    if *addr != 0 {
        let bytes = unsafe {
            bpf_probe_read_user(*addr as *const &[u8])
            .map_err(|_| 1u32)?
        };
        info!(&ctx, "-----> Buffer Size: {}", bytes.len());
        info!(&ctx, "--> Pointer to Buffer: {}", bytes.as_ptr() as usize);
        let first_byte = unsafe {
            bpf_probe_read_user(bytes.as_ptr())
            .map_err(|_| 1u32)?
        };
        info!(&ctx, "***** First Byte: {}", first_byte);
    }
    Ok(0)
}

fn try_quicprobe(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "recv() returned in quiche-client");
    let read : *const Option<usize> = ctx.ret().ok_or(1u32)?;
    let bytes = unsafe {
        bpf_probe_read_user(&(*read) as *const Option<usize>)
        .map_err(|_| 1u32)?
    };
    let n : usize = match bytes {
        Some(n) => n,
        None => 0
    };
    info!(&ctx, "Bytes read: {}", n); 
    let pid_gid = bpf_get_current_pid_tgid();
    let buff_arg_addr = unsafe {
        BUFFER_PTR.get(&pid_gid)
    };
    match buff_arg_addr {
        Some(addr) => read_buffer(ctx, addr),
        None => { info!(&ctx, "Unable to get ptr"); Ok(0) }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
