use anyhow::Result;
use std::fs;

pub struct ProcInfo {
    pub tgid: u32,
    pub ppid: u32,
    pub start_time_ns: u64,
    pub comm: String,
    pub exe: String,
    pub argv: Vec<String>,
    pub uid: u32,
}

fn clock_ticks_to_ns(ticks: u64) -> u64 {
    const NS_PER_TICK: u64 = 1_000_000_000 / 100;
    ticks * NS_PER_TICK
}

fn parse_stat(content: &str) -> Option<(u32, u64)> {
    let close = content.rfind(')')?;
    let rest = content.get(close + 2..)?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let ppid: u32 = fields.get(1)?.parse().ok()?;
    let starttime: u64 = fields.get(19)?.parse().ok()?;
    Some((ppid, starttime))
}

fn read_uid(pid: u32) -> u32 {
    let path = format!("/proc/{pid}/status");
    let Ok(content) = fs::read_to_string(&path) else {
        return 0;
    };
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            if let Some(first) = rest.split_whitespace().next() {
                return first.parse().unwrap_or(0);
            }
        }
    }
    0
}

fn read_argv(pid: u32) -> Vec<String> {
    let path = format!("/proc/{pid}/cmdline");
    let Ok(bytes) = fs::read(&path) else {
        return Vec::new();
    };
    bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

pub fn snapshot() -> Result<Vec<ProcInfo>> {
    let mut out = Vec::new();

    for entry in fs::read_dir("/proc")? {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else { continue };

        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        let Some((ppid, ticks)) = parse_stat(&stat) else {
            continue;
        };

        let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim_end().to_string())
            .unwrap_or_default();

        let exe = fs::read_link(format!("/proc/{pid}/exe"))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        out.push(ProcInfo {
            tgid: pid,
            ppid,
            start_time_ns: clock_ticks_to_ns(ticks),
            comm,
            exe,
            argv: read_argv(pid),
            uid: read_uid(pid),
        });
    }

    Ok(out)
}
