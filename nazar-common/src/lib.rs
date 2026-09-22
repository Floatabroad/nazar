#![no_std]

pub const MAX_ARGS: usize = 20;
pub const ARG_LEN: usize = 128;
pub const ARGS_LEN: usize = 2048;
pub const EVENT_EXEC: u32 = 0;
pub const EVENT_FORK: u32 = 1;
pub const EVENT_EXIT: u32 = 2;
pub const EVENT_PROC_EXEC: u32 = 3;
pub const EVENT_LSM_EXEC: u32 = 6;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventHeader {
    pub kind: u32,
    pub tgid: u32,
    pub pid: u32,
    pub _pad: u32,
    pub timestamp: u64,
    pub start_time: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LsmExecEvent {
    pub header: EventHeader,
    pub blocked: u32,
    pub _pad2: u32,
    pub filename: [u8; 256],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LsmExecEvent {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub header: EventHeader,
    pub uid: u32,
    pub gid: u32,
    pub argc: u32,
    pub args_len: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
    pub args: [u8; ARGS_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcExecEvent {
    pub header: EventHeader,
    pub old_pid: u32,
    pub data_loc_raw: u32,
    pub filename: [u8; 256],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ForkEvent {
    pub header: EventHeader,
    pub parent_pid: u32,
    pub child_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExitEvent {
    pub header: EventHeader,
    pub exiting_pid: u32,
    pub group_dead: u32,
    pub comm: [u8; 16],
}

pub const EVENT_CONNECT: u32 = 5;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub header: EventHeader,

    pub addr: [u32; 4],

    pub port: u32,
    pub family: u32,
    pub protocol: u32,
    pub _pad2: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ForkEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExitEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcExecEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for EventHeader {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}

pub const EVENT_OPEN: u32 = 4;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenEvent {
    pub header: EventHeader,
    pub flags: u32,
    pub _pad2: u32,
    pub filename: [u8; 256],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for OpenEvent {}
