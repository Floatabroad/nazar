use aya::{programs::{CgroupSockAddr, CgroupAttachMode},maps::RingBuf, programs::TracePoint};
use log::debug;
use nazar_common::{
    ConnectEvent, EventHeader, ExecEvent, ExitEvent, ForkEvent, OpenEvent, ProcExecEvent,
    ARGS_LEN, EVENT_CONNECT, EVENT_EXEC, EVENT_EXIT, EVENT_FORK, EVENT_OPEN, EVENT_PROC_EXEC, LsmExecEvent, EVENT_LSM_EXEC
};
use tokio::{io::unix::AsyncFd, signal};
mod btf;
mod proc_table;
use proc_table::{ProcKey, ProcTable};
mod procfs;
mod detect;
use detect::Engine;
mod rules;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe  { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim)};
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/nazar-agent"
                )))?;
    {
        use aya::maps::Array;
        let mut offsets: Array<_, u32> = Array::try_from(ebpf.map_mut("OFFSETS").unwrap())?;
        let start_boottime = btf::kernel_field_offset("task_struct", "start_boottime")?;
        offsets.set(0, start_boottime, 0)?;
        println!("task_struct.start_boottime @ byte {start_boottime}");
        offsets.set(1, std::process::id(), 0)?;
                let bprm_filename = btf::kernel_field_offset("linux_binprm", "filename")?;
        offsets.set(2, bprm_filename, 0)?;
        println!("linux_binprm.filename @ byte {bprm_filename}");

        let enforce = if std::env::var("NAZAR_ENFORCE").is_ok() { 1u32 } else { 0 };
        offsets.set(3, enforce, 0)?;
        if enforce != 0 {
            println!("ENFORCEMENT ENABLED");
        }
    }
    {
        use aya::maps::HashMap as AyaHashMap;
        let mut deny: AyaHashMap<_, [u8; 256], u8> =
            AyaHashMap::try_from(ebpf.map_mut("EXEC_DENYLIST").unwrap())?;

        if let Ok(list) = std::env::var("NAZAR_DENY") {
            for path in list.split(',').filter(|s| !s.is_empty()) {
                let mut key = [0u8; 256];
                let bytes = path.as_bytes();
                if bytes.len() >= 256 {
                    eprintln!("deny path too long, skipping: {path}");
                    continue;
                }
                key[..bytes.len()].copy_from_slice(bytes);
                deny.insert(&key, 1u8, 0)?;
                println!("deny: {path}");
            }
        }
    }
        {
        let p: &mut TracePoint = ebpf.program_mut("nazar").unwrap().try_into()?;
        p.load()?;
        p.attach("syscalls", "sys_enter_execve")?;
    }
    {
        let p: &mut TracePoint = ebpf.program_mut("nazar_proc_exec").unwrap().try_into()?;
        p.load()?;
        p.attach("sched", "sched_process_exec")?;
    }
    {
        let p: &mut TracePoint = ebpf.program_mut("nazar_fork").unwrap().try_into()?;
        p.load()?;
        p.attach("sched", "sched_process_fork")?;
    }
    {
        let p: &mut TracePoint = ebpf.program_mut("nazar_exit").unwrap().try_into()?;
        p.load()?;
        p.attach("sched", "sched_process_exit")?;
    }
    {
        let p: &mut TracePoint = ebpf.program_mut("nazar_open").unwrap().try_into()?;
        p.load()?;
        p.attach("syscalls", "sys_enter_openat")?;
    }
    {
        let cgroup = std::fs::File::open("/sys/fs/cgroup")?;
        let p: &mut CgroupSockAddr = ebpf.program_mut("nazar_connect4").unwrap().try_into()?;
        p.load()?;
        p.attach(&cgroup, CgroupAttachMode::Single)?;
    }
    {
        let cgroup = std::fs::File::open("/sys/fs/cgroup")?;
        let p: &mut CgroupSockAddr = ebpf.program_mut("nazar_connect6").unwrap().try_into()?;
        p.load()?;
        p.attach(&cgroup, CgroupAttachMode::Single)?;
    }
    {
        let btf = aya::Btf::from_sys_fs()?;
        let p: &mut aya::programs::Lsm =
            ebpf.program_mut("nazar_bprm").unwrap().try_into()?;
        p.load("bprm_check_security", &btf)?;
        p.attach()?;
    }

    

    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let mut ring = AsyncFd::new(ring)?;

    println!("Waiting for ctrl-c...");
    let mut table = ProcTable::new();
    match procfs::snapshot() {
        Ok(procs) => {
            let n = procs.len();
            table.seed(procs);
            println!("seeded {n} processes from /proc");
        }
        Err(e) => eprintln!("failed to seed from /proc: {e}"),
    }
        let mut open_count: u64 = 0;
    let started = std::time::Instant::now();
        let json_output = std::env::var("NAZAR_JSON").is_ok();
            let debug_events = std::env::var("NAZAR_DEBUG").is_ok();
        let rules_path = std::env::var("NAZAR_RULES")
        .unwrap_or_else(|_| "nazar-agent/rules.toml".to_string());
    let mut engine = Engine::load(&rules_path)?;
    println!("loaded {} detection rules", engine.rule_count());
        let mut expiry = tokio::time::interval(std::time::Duration::from_secs(10));
            let mut sigterm = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::terminate()
    )?;
    loop {
        tokio::select!{
            _ = signal::ctrl_c() => break,
            _ = sigterm.recv() => break,
            _ = expiry.tick() => {
                engine.expire();
                table.reap(std::time::Duration::from_secs(60));
            },
            guard = ring.readable_mut() => {
                let mut guard = guard?;
                let ring = guard.get_inner_mut();
                               while let Some(item) = ring.next() {
                    let bytes: &[u8] = item.as_ref();
                    if bytes.len() < core::mem::size_of::<EventHeader>() {
                        continue;
                    }
                    let header: EventHeader = unsafe {
                        core::ptr::read_unaligned(bytes.as_ptr() as *const EventHeader)
                    };

                    match header.kind {
                        EVENT_EXEC => {
                            if bytes.len() < core::mem::size_of::<ExecEvent>() {
                                continue;
                            }
                            let event: ExecEvent = unsafe {
                                core::ptr::read_unaligned(bytes.as_ptr() as *const ExecEvent)
                            };
                            let args_len = (event.args_len as usize).min(ARGS_LEN);
                            let args: Vec<&str> = event.args[..args_len]
                                .split(|&b| b == 0)
                                .filter(|s| !s.is_empty())
                                .map(|s| core::str::from_utf8(s).unwrap_or("<invalid>"))
                                .collect();
                                
                                                        let key = ProcKey {
                                tgid: event.header.tgid,
                                start_time: event.header.start_time,
                            };
                            let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
                            table.on_exec(key, cstr(&event.comm), event.uid, argv);
    
                            }
                        EVENT_PROC_EXEC => {
                            if bytes.len() < core::mem::size_of::<ProcExecEvent>() {
                                continue;
                            }
                            let event: ProcExecEvent = unsafe {
                                core::ptr::read_unaligned(bytes.as_ptr() as *const ProcExecEvent)
                            };
                                                                                   
                                                                   let key = ProcKey {
                                tgid: event.header.tgid,
                                start_time: event.header.start_time,
                            };
                                                      

                                                        if let Some(alert) = engine.on_exec(&table, key, cstr(&event.filename)) {
                                emit(&alert, json_output);
                            }
                            table.on_proc_exec(key, cstr(&event.filename));

                            let chain: Vec<String> = table
                                .ancestry(key)
                                .iter()
                                .map(|n| {
                                    if n.exe.is_empty() { n.comm.clone() } else { n.exe.clone() }
                                })
                                .collect();
                                                        if debug_events {
                                println!("exec {} <- {}", cstr(&event.filename), chain.join(" <- "));
                            }


                                                }
                        EVENT_FORK => {
                            if bytes.len() < core::mem::size_of::<ForkEvent>() { continue; }
                            let event: ForkEvent = unsafe {
                                core::ptr::read_unaligned(bytes.as_ptr() as *const ForkEvent)
                            };
                                                        table.on_fork(
                                event.header.tgid,
                                event.header.start_time,
                                event.child_pid,
                            );
                        }
                        EVENT_EXIT => {
                            if bytes.len() < core::mem::size_of::<ExitEvent>() { continue; }
                            let event: ExitEvent = unsafe {
                                core::ptr::read_unaligned(bytes.as_ptr() as *const ExitEvent)
                            };
                                                       let key = ProcKey {
                                tgid: event.header.tgid,
                                start_time: event.header.start_time,
                            };
                            table.on_exit(key, event.group_dead != 0);
                            engine.expire();
                        }
                        EVENT_OPEN => {
                            if bytes.len() < core::mem::size_of::<OpenEvent>() {continue;}
                            let event: OpenEvent = unsafe {
                                core::ptr::read_unaligned(bytes.as_ptr() as *const OpenEvent)
                            };
                                                       open_count += 1;
                            let key = ProcKey {
                                tgid: event.header.tgid,
                                start_time: event.header.start_time,
                            };
                                                       if let Some(alert) = engine.on_write(&table, key, cstr(&event.filename)) {
                                emit(&alert, json_output);
                            }
                        }
                        EVENT_CONNECT => {
                            if bytes.len() < core::mem::size_of::<ConnectEvent>() { continue; }
                            let event: ConnectEvent = unsafe {
                                core::ptr::read_unaligned(bytes.as_ptr() as *const ConnectEvent)
                            };
                            let port = u16::from_be(event.port as u16);
                            let addr = if event.family == 10 {
                                let mut b = [0u8; 16];
                                for (i, w) in event.addr.iter().enumerate() {
                                    b[i*4..i*4+4].copy_from_slice(&w.to_ne_bytes());
                                }
                                std::net::IpAddr::from(b).to_string()
                            } else {
                                std::net::IpAddr::from(event.addr[0].to_ne_bytes()).to_string()
                            };
                            let key = ProcKey {
                                tgid: event.header.tgid,
                                start_time: event.header.start_time,
                            };
                            let who = table.resolve(&key)
                                .map(|n| if n.exe.is_empty() { n.comm.clone() } else { n.exe.clone() })
                                .unwrap_or_else(|| format!("tgid {}", event.header.tgid));
                                                       if let Some(alert) = engine.on_connect(&table, key, &addr, port) {
                                emit(&alert, json_output);
                            }
                                                                                   if debug_events {
                                println!("connect {addr}:{port} proto={} <- {who}", event.protocol);
                            }
                        }
                        EVENT_LSM_EXEC => {
                            if bytes.len() < core::mem::size_of::<LsmExecEvent>() { continue; }
                            let event: LsmExecEvent = unsafe {
                                core::ptr::read_unaligned(bytes.as_ptr() as *const LsmExecEvent)
                            };
                            if event.blocked != 0 {
                                println!(
                                    "[BLOCKED] exec denied: {} (tgid {})",
                                    cstr(&event.filename),
                                    event.header.tgid
                                );
                            } else if debug_events {
                                println!("lsm_exec {}", cstr(&event.filename));
                            }
                        }
                        other => {
                            eprintln!("unknown event kind={other}");
                        }
                    }
                }
                guard.clear_ready();
            }
        }
    }
    {
        let inner = ring.get_mut();
        let mut drained = 0usize;
        while inner.next().is_some() {
            drained += 1;
        }
        if drained > 0 && debug_events {
            println!("drained {drained} events on shutdown");
        }
    }
        if debug_events {
        let secs = started.elapsed().as_secs_f64();
        println!("openat: {} events in {:.1}s = {:.0}/sec", open_count, secs, open_count as f64 / secs);
    
    
        }
        {
        use aya::maps::Array;
        let stats: Array<_, u64> = Array::try_from(ebpf.map("STATS").unwrap())?;
        let dropped = stats.get(&0, 0).unwrap_or(0);
        if dropped > 0 {
            println!("WARNING: {dropped} events dropped (ring buffer full)");
        } else {
            println!("no events dropped");
        }
    }
    println!("Exiting...");
    Ok(())
}

fn cstr(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..end]).unwrap_or("<invalid>")
}
fn emit(alert: &detect::Alert, json: bool) {
    if json {
        println!("{}", alert.to_json());
    } else {
        println!("{}", alert.render());
    }
}
