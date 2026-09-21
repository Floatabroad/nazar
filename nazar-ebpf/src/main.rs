#![no_std]
#![no_main]
use nazar_common::{ExecEvent, ARG_LEN,ARGS_LEN, MAX_ARGS, EVENT_EXEC, ProcExecEvent, EVENT_PROC_EXEC, ForkEvent, ExitEvent, EVENT_FORK, EVENT_EXIT, OpenEvent, EVENT_OPEN,ConnectEvent, EVENT_CONNECT,LsmExecEvent,EVENT_LSM_EXEC};
use aya_ebpf::{
    macros::{cgroup_sock_addr,map,tracepoint, lsm},
    maps::{Array,RingBuf, HashMap as BpfHashMap},
    programs::{TracePointContext, SockAddrContext, LsmContext},
    EbpfContext,
};

const OFF_START_BOOTTIME: u32 = 0;
const CFG_SELF_TGID: u32 = 1;

const O_WRONLY: u32 = 0x1;
const O_RDWR: u32 = 0x2;
const O_CREAT: u32 = 0x40;
const O_TRUNC: u32 = 0x200;
const WRITE_FLAGS: u32 = O_WRONLY | O_RDWR | O_CREAT | O_TRUNC;
const OFF_BPRM_FILENAME: u32 = 2;
const CFG_ENFORCE: u32 = 3;


#[map]
static EXEC_DENYLIST: BpfHashMap<[u8; 256], u8> =
    BpfHashMap::with_max_entries(64, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[map]
static OFFSETS: Array<u32> = Array::with_max_entries(8, 0);

#[map]
static STATS: Array<u64> = Array::with_max_entries(4, 0);

const STAT_RINGBUF_FULL: u32 = 0;

fn bump(idx: u32) {
    if let Some(slot) = STATS.get_ptr_mut(idx) {
        unsafe { *slot += 1 };
    }
}
#[cgroup_sock_addr(connect4)]
pub fn nazar_connect4(ctx: SockAddrContext) -> i32 {
    let sa = ctx.sock_addr;
    let addr = unsafe { [(*sa).user_ip4, 0, 0, 0] };
    emit_connect(&ctx, addr);
    1
}

#[cgroup_sock_addr(connect6)]
pub fn nazar_connect6(ctx: SockAddrContext) -> i32 {
    let sa = ctx.sock_addr;
    let addr = unsafe {
        [
            (*sa).user_ip6[0],
            (*sa).user_ip6[1],
            (*sa).user_ip6[2],
            (*sa).user_ip6[3],
        ]
    };
    emit_connect(&ctx, addr);
    1
}

fn emit_connect(ctx: &SockAddrContext, addr: [u32; 4]) {
    let sa = ctx.sock_addr;
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    if let Some(self_tgid) = OFFSETS.get(CFG_SELF_TGID) {
        if *self_tgid != 0 && *self_tgid == tgid {
            return;
        }
    }

        let Some(mut entry) = EVENTS.reserve::<ConnectEvent>(0) else {
        bump(STAT_RINGBUF_FULL);
        return;
    };
    let ptr = entry.as_mut_ptr();

    unsafe {
        (&raw mut (*ptr).header.kind).write(EVENT_CONNECT);
        (&raw mut (*ptr).header.tgid).write(tgid);
        (&raw mut (*ptr).header.pid).write(pid_tgid as u32);
        (&raw mut (*ptr).header._pad).write(0);
        (&raw mut (*ptr).header.timestamp).write(
            aya_ebpf::helpers::bpf_ktime_get_ns()
        );
        (&raw mut (*ptr).header.start_time).write(current_start_time());

        (&raw mut (*ptr).family).write((*sa).family);
        (&raw mut (*ptr).port).write((*sa).user_port);
        (&raw mut (*ptr).protocol).write((*sa).protocol);
        (&raw mut (*ptr)._pad2).write(0);

        (&raw mut (*ptr).addr[0]).write(addr[0]);
        (&raw mut (*ptr).addr[1]).write(addr[1]);
        (&raw mut (*ptr).addr[2]).write(addr[2]);
        (&raw mut (*ptr).addr[3]).write(addr[3]);
    }

    entry.submit(0);
}

#[tracepoint]
pub fn nazar(ctx: TracePointContext) -> u32 {
    match try_nazar(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_nazar(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;
    
    let uid_gid = unsafe { aya_ebpf::helpers::generated::bpf_get_current_uid_gid()};
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;
    
    let filename_ptr: u64 = unsafe {ctx.read_at(16).map_err(|_| 1u32)?};

        let mut entry = match EVENTS.reserve::<ExecEvent>(0) {
        Some(entry) => entry,
        None => {
            bump(STAT_RINGBUF_FULL);
            return Err(1);
        }
    };

    let ptr = entry.as_mut_ptr();

    unsafe {

        (&raw mut (*ptr).header.kind).write(EVENT_EXEC);
        (&raw mut (*ptr).header.tgid).write(tgid);
        (&raw mut (*ptr).header.pid).write(pid);
        (&raw mut (*ptr).header._pad).write(0);
        
        (&raw mut (*ptr).header.timestamp).write(
            aya_ebpf::helpers::bpf_ktime_get_ns()
        );
        (&raw mut (*ptr).header.start_time).write(current_start_time());
        (&raw mut (*ptr).uid).write(uid);
        (&raw mut (*ptr).gid).write(gid);


        let ret = aya_ebpf::helpers::generated::bpf_get_current_comm(
            (&raw mut (*ptr).comm).cast(),
            16,
        );
        if ret != 0 {
            entry.discard(0);
            return Err(1);
        }
        let ret = aya_ebpf::helpers::generated::bpf_probe_read_user_str(
            (&raw mut (*ptr).filename).cast(),
            256,
            filename_ptr as *const _,
            );
            if ret < 0 {
                entry.discard(0);
                return Err(1);
        }
        let argv_ptr: u64 = match ctx.read_at(24) {
            Ok(v) => v,
            Err(_) => {
                entry.discard(0);
                return Err(1);
            }
        };
        let mut argc: u32 = 0;
        let mut cursor: usize = 0;
        
        for i in 0..MAX_ARGS {
            let mut arg_ptr: u64 = 0;
            let ret = aya_ebpf::helpers::generated::bpf_probe_read_user(
                (&raw mut arg_ptr).cast(),
                8,
                (argv_ptr as *const u8).add(i*8) as *const _,
                );
            if ret < 0 || arg_ptr == 0{
                break;
            }
            if cursor + ARG_LEN > ARGS_LEN {
                break;
            } 
            let off = cursor & (ARGS_LEN - 1);
            let dst = (&raw mut (*ptr).args).cast::<u8>().add(off);

            let ret = aya_ebpf::helpers::generated::bpf_probe_read_user_str(
                dst.cast(),
                ARG_LEN as u32,
                arg_ptr as *const _,
                );
            if ret <= 0 {
                break;
            }
            cursor += ret as usize;
            argc += 1;
        }

        

        (&raw mut (*ptr).argc).write(argc);
        (&raw mut (*ptr).args_len).write(cursor as u32);


        
    }

    entry.submit(0);
    Ok(0)
}

#[tracepoint]
pub fn nazar_proc_exec(ctx: TracePointContext) -> u32 {
    match try_proc_exec(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_proc_exec(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;

    let data_loc: u32 = unsafe { ctx.read_at(8).map_err(|_| 1u32)? };
    let filename_off = (data_loc & 0xFFFF) as usize;
    let old_pid: u32 = unsafe { ctx.read_at(16).map_err(|_| 1u32)? };

    
    let mut entry = match EVENTS.reserve::<ProcExecEvent>(0) {
        Some(entry) => entry,
        None => {
            bump(STAT_RINGBUF_FULL);
            return Err(1);
        }
    };
    let ptr = entry.as_mut_ptr();

    unsafe {
        (&raw mut (*ptr).header.kind).write(EVENT_PROC_EXEC);
        (&raw mut (*ptr).header.tgid).write(tgid);
        (&raw mut (*ptr).header.pid).write(pid);
        (&raw mut (*ptr).header._pad).write(0);
        (&raw mut (*ptr).header.timestamp).write(
            aya_ebpf::helpers::bpf_ktime_get_ns()
        );
                (&raw mut (*ptr).header.start_time).write(current_start_time());
        (&raw mut (*ptr).old_pid).write(old_pid);
        (&raw mut (*ptr).data_loc_raw).write(data_loc); 
             
                let src = ctx.as_ptr().cast::<u8>().add(filename_off);
        let ret = aya_ebpf::helpers::generated::bpf_probe_read_kernel_str(
            (&raw mut (*ptr).filename).cast(),
            256,
            src.cast(),
        );
        if ret < 0 {
            entry.discard(0);
            return Err(1);
        }
    }

    entry.submit(0);
    Ok(0)
}

#[tracepoint]
pub fn nazar_fork(ctx: TracePointContext) -> u32 {
    match try_fork(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_fork(ctx: TracePointContext) -> Result<u32, u32> {
    let parent_pid: u32 = unsafe {ctx.read_at(12).map_err(|_| 1u32)?};
    let child_pid: u32 = unsafe {ctx.read_at(20).map_err(|_| 1u32)?};

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
        let mut entry = match EVENTS.reserve::<ForkEvent>(0) {
        Some(entry) => entry,
        None => {
            bump(STAT_RINGBUF_FULL);
            return Err(1);
        }
    };
    let ptr = entry.as_mut_ptr();

    unsafe {
         (&raw mut (*ptr).header.kind).write(EVENT_FORK);
        (&raw mut (*ptr).header.tgid).write((pid_tgid >> 32) as u32);
        (&raw mut (*ptr).header.pid).write(pid_tgid as u32);
        (&raw mut (*ptr).header._pad).write(0);
        (&raw mut (*ptr).header.timestamp).write(
            aya_ebpf::helpers::bpf_ktime_get_ns()
        );
        (&raw mut (*ptr).header.start_time).write(current_start_time());
        (&raw mut (*ptr).parent_pid).write(parent_pid);
        (&raw mut (*ptr).child_pid).write(child_pid);
    }
    entry.submit(0);
    Ok(0)
} 
#[tracepoint]
pub fn nazar_exit(ctx: TracePointContext) -> u32 {
    match try_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_exit(ctx: TracePointContext) -> Result<u32, u32> {
     let exiting_pid: u32 = unsafe { ctx.read_at(24).map_err(|_| 1u32)? };
    let group_dead: u8 = unsafe { ctx.read_at(32).map_err(|_| 1u32)? };

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();

     let mut entry = match EVENTS.reserve::<ExitEvent>(0) {
        Some(entry) => entry,
        None => {
            bump(STAT_RINGBUF_FULL);
            return Err(1);
        }
    };
    let ptr = entry.as_mut_ptr();

    unsafe {
        (&raw mut (*ptr).header.kind).write(EVENT_EXIT);
        (&raw mut (*ptr).header.tgid).write((pid_tgid >> 32) as u32);
        (&raw mut (*ptr).header.pid).write(pid_tgid as u32);
        (&raw mut (*ptr).header._pad).write(0);
        (&raw mut (*ptr).header.timestamp).write(
            aya_ebpf::helpers::bpf_ktime_get_ns()
        );
                (&raw mut (*ptr).header.start_time).write(current_start_time());
        (&raw mut (*ptr).exiting_pid).write(exiting_pid);
        (&raw mut (*ptr).group_dead).write(group_dead as u32);

        let src = ctx.as_ptr().cast::<u8>().add(8);
        let ret = aya_ebpf::helpers::generated::bpf_probe_read_kernel(
            (&raw mut (*ptr).comm).cast(),
            16,
            src.cast(),
        );
        if ret < 0 {
            entry.discard(0);
            return Err(1);
        }
    }

    entry.submit(0);
    Ok(0)
}

fn current_start_time() -> u64 {
    let off = match OFFSETS.get(OFF_START_BOOTTIME) {
        Some(v) if *v != 0 => *v as usize,
        _ => return 0,
    };

    let task = unsafe { aya_ebpf::helpers::generated::bpf_get_current_task() };
    if task == 0 {
        return 0;
    }

    let mut out: u64 = 0;
    let ret = unsafe {
        aya_ebpf::helpers::generated::bpf_probe_read_kernel(
            (&raw mut out).cast(),
            8,
            (task as *const u8).add(off) as *const _,
        )
    };
    if ret < 0 { 0 } else { out }
}


#[tracepoint]
pub fn nazar_open(ctx: TracePointContext) -> u32 {
    match try_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_open(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    if let Some(self_tgid) = OFFSETS.get(CFG_SELF_TGID) {
        if *self_tgid != 0 && *self_tgid == tgid {
            return Ok(0);
        }
    }

    let flags: u64 = unsafe { ctx.read_at(32).map_err(|_| 1u32)? };
    let flags = flags as u32;

    if flags & WRITE_FLAGS == 0 {
        return Ok(0);
    }

    let filename_ptr: u64 = unsafe { ctx.read_at(24).map_err(|_| 1u32)? };

       let mut entry = match EVENTS.reserve::<OpenEvent>(0) {
        Some(entry) => entry,
        None => {
            bump(STAT_RINGBUF_FULL);
            return Err(1);
        }
    };
    let ptr = entry.as_mut_ptr();

    unsafe {
        (&raw mut (*ptr).header.kind).write(EVENT_OPEN);
        (&raw mut (*ptr).header.tgid).write((pid_tgid >> 32) as u32);
        (&raw mut (*ptr).header.pid).write(pid_tgid as u32);
        (&raw mut (*ptr).header._pad).write(0);
        (&raw mut (*ptr).header.timestamp).write(
            aya_ebpf::helpers::bpf_ktime_get_ns()
        );
        (&raw mut (*ptr).header.start_time).write(current_start_time());
        (&raw mut (*ptr).flags).write(flags as u32);
        (&raw mut (*ptr)._pad2).write(0);

        let ret = aya_ebpf::helpers::generated::bpf_probe_read_user_str(
            (&raw mut (*ptr).filename).cast(),
            256,
            filename_ptr as *const _,
        );
        if ret < 0 {
            entry.discard(0);
            return Err(1);
        }
    }

    entry.submit(0);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo)-> ! {
    loop{}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";


#[lsm(hook = "bprm_check_security")]
pub fn nazar_bprm(ctx: LsmContext) -> i32 {
    match try_bprm(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_bprm(ctx: &LsmContext) -> Result<i32, i32> {
    let prev: i32 = unsafe { ctx.arg(1) };
    if prev != 0 {
        return Ok(prev);
    }

    let bprm: *const u8 = unsafe { ctx.arg(0) };
    if bprm.is_null() {
        return Ok(0);
    }

    let off = match OFFSETS.get(OFF_BPRM_FILENAME) {
        Some(v) if *v != 0 => *v as usize,
        _ => return Ok(0),
    };

    let mut name_ptr: u64 = 0;
    let ret = unsafe {
        aya_ebpf::helpers::generated::bpf_probe_read_kernel(
            (&raw mut name_ptr).cast(),
            8,
            bprm.add(off) as *const _,
        )
    };
    if ret < 0 || name_ptr == 0 {
        return Ok(0);
    }

    let Some(mut entry) = EVENTS.reserve::<LsmExecEvent>(0) else {
        bump(STAT_RINGBUF_FULL);
        return Ok(0);
    };
    let ptr = entry.as_mut_ptr();

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();

    let decision = unsafe {
        (&raw mut (*ptr).header.kind).write(EVENT_LSM_EXEC);
        (&raw mut (*ptr).header.tgid).write((pid_tgid >> 32) as u32);
        (&raw mut (*ptr).header.pid).write(pid_tgid as u32);
        (&raw mut (*ptr).header._pad).write(0);
        (&raw mut (*ptr).header.timestamp).write(
            aya_ebpf::helpers::bpf_ktime_get_ns()
        );
        (&raw mut (*ptr).header.start_time).write(current_start_time());
        (&raw mut (*ptr)._pad2).write(0);

        let n = aya_ebpf::helpers::generated::bpf_probe_read_kernel_str(
            (&raw mut (*ptr).filename).cast(),
            256,
            name_ptr as *const _,
        );
        if n < 0 {
            entry.discard(0);
            return Ok(0);
        }

        let enforcing = OFFSETS
            .get(CFG_ENFORCE)
            .map(|v| *v != 0)
            .unwrap_or(false);

        let listed = EXEC_DENYLIST
            .get(&*(&raw const (*ptr).filename))
            .is_some();

        let blocked = if enforcing && listed { 1u32 } else { 0u32 };
        (&raw mut (*ptr).blocked).write(blocked);
        blocked
    };

    entry.submit(0);

    if decision != 0 {
        Ok(-1)
    } else {
        Ok(0)
    }
}
