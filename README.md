# nazar

An eBPF runtime telemetry and detection agent for Linux, written in Rust with [aya](https://aya-rs.dev).

`nazar` watches process execution, file writes and outbound connections from the kernel, reconstructs the process tree in userspace, and evaluates declarative detection rules against the correlated stream. Rules carry MITRE ATT&CK technique IDs. A BPF-LSM hook can optionally deny execution rather than just record it.

The name is Turkish: *nazar* is the eye that watches for harm.

---

## What it does

```
kernel                                  userspace
──────────────────────────────────      ─────────────────────────────────
sys_enter_execve      ─┐
sched_process_exec     │
sched_process_fork     ├─► ring buffer ─► process table ─► rule engine ─► alerts
sched_process_exit     │    (1 MiB)       (tgid,start_time)   (rules.toml)
sys_enter_openat       │
cgroup/connect4,6      │
lsm/bprm_check_security┘  └─► may return -EPERM
```

Example output:

```
[CRITICAL] writable_exec_then_outbound (T1059,T1071,T1204)
    /tmp/c connected out to 104.20.23.154:443 0.1s after exec
    chain: /bin/zsh <- /usr/bin/kitty <- /usr/bin/Hyprland <- /usr/bin/start-hyprland
           <- /usr/lib/sddm/sddm-helper <- /usr/bin/sddm <- /usr/lib/systemd/systemd
```

Every alert carries the full ancestry back to PID 1.

With `NAZAR_JSON=1`, the same alert is emitted as one JSON object per line:

```json
{"timestamp_ms":1789296043519,"rule_id":"hidden_file_exec","severity":"high","attack":["T1564.001"],"message":"executed hidden file /tmp/.j","ancestry":["/bin/zsh","/usr/bin/kitty","..."]}
```

`NAZAR_DEBUG=1` additionally traces the raw event stream; by default the agent emits alerts only.

---

## Detection rules

Rules live in `nazar-agent/rules.toml` and are loaded at startup. Rule order is precedence — the first match wins, so specific rules sit above general ones.

| Rule | Severity | ATT&CK | Trigger |
|---|---|---|---|
| `hidden_file_exec` | HIGH | T1564.001 | executing a dotfile |
| `path_shadowing` | HIGH | T1574.007 | a system command name (`ps`, `git`, `sudo`…) resolved to a user-writable path |
| `shell_under_service` | CRITICAL | T1059 | a shell spawned beneath nginx / postgres / php-fpm / etc. |
| `exec_from_writable_dir` | MEDIUM | T1059, T1204 | exec from `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user` |
| `persistence_write` | HIGH | T1543, T1053, T1546.004 | writes to systemd units, cron, `profile.d`, autostart, shell rc files |
| `shell_outbound_connection` | HIGH | T1059.004, T1071 | the process opening the socket *is* a shell |
| `writable_exec_then_outbound` | CRITICAL | T1059, T1071, T1204 | writable-dir exec followed by an outbound connection within 30s |

`shell_under_service` is the one rule not exercised on the development box — it needs a network-facing service to spawn a shell. The other six are verified end to end.

### Rule format

Sigma-shaped, TOML-encoded. Within `match`: every condition in `all` must hold, at least one in `any` must hold when `any` is non-empty, and no condition in `not` may hold.

```toml
[[rule]]
id = "path_shadowing"
severity = "high"
attack = ["T1574.007"]
on = "exec"
message = "system command '{basename}' executed from writable {path}"
[rule.match]
all = [
  { field = "path", op = "prefix", values = ["/tmp/", "/home/", "/dev/shm/"] },
  { field = "basename", op = "exact", values = ["ps", "git", "sudo", "curl"] },
]
not = [
  { field = "path", op = "contains", values = ["/JetBrains/"] },
]
```

- **Fields:** `path`, `basename`, `ancestry_path`, `ancestry_basename`, `uid`, `dst_ip`, `dst_port`
- **Operators:** `prefix`, `suffix`, `contains`, `exact`
- **Events:** `exec`, `write`, `connect`
- **Correlation:** `correlate = { after = "<rule_id>", within = "30s", same_process = true }`

Correlation targets and durations are validated at load, so a typo fails at startup rather than silently never firing.

---

## Enforcement

Requires `CONFIG_BPF_LSM=y` and `bpf` in the active LSM stack (`cat /sys/kernel/security/lsm`).

```bash
cp /bin/echo /tmp/blocked-test
NAZAR_ENFORCE=1 NAZAR_DENY=/tmp/blocked-test ./target/debug/nazar-agent
```

```
$ /tmp/blocked-test hello
zsh: operation not permitted: /tmp/blocked-test
$ echo $?
127
```

```
[BLOCKED] exec denied: /tmp/blocked-test (tgid 18234)
```

The `lsm/bprm_check_security` program runs at the security decision point, before the binary is loaded, and returns `-EPERM` when the resolved path is in the deny list. It fires *ahead of* `sched_process_exec`, which is the point: the tracepoint sees an exec that already happened, the LSM hook sees one that can still be stopped.

Enforcement is off by default. With `NAZAR_ENFORCE` unset the same hook only observes, and the deny list is ignored.

The program also honours the previous LSM's verdict. The last argument to an LSM hook is the return value of whichever LSM ran before it; a non-zero prior decision is passed through unchanged rather than overridden.

---

## Overhead

Measured with `hyperfine`, 50 runs and 3 warmup runs per measurement, on a fork-heavy workload: 500 sequential `fork`+`exec` of `/bin/true`.

| workload | agent off | agent on | delta |
|---|---|---|---|
| 500 × fork+exec | 219.0 ms | 223.7 ms | +4.7 ms (2.1%) |

Three independent pairs gave +5.0, +4.7 and +4.4 ms, so the figure is reproducible rather than a single lucky run. One further pair was discarded: σ jumped to 8.5 ms with a 215–254 ms range, which is background load rather than measurement.

Each run drives roughly 2000 probe invocations, putting the cost at about **2.4 µs per event** — in a debug build, on a desktop with a browser and IDE running. A release build and a quiet machine would both be kinder.

Resident memory as a systemd service: 8.8 MB.

---

## Running

Requires kernel 5.15+ with `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_BPF_LSM=y` and cgroup v2.

```bash
rustup toolchain install nightly-2026-06-01
rustup component add rust-src --toolchain nightly-2026-06-01
cargo install bpf-linker

cargo build
sudo ./target/debug/nazar-agent
```

**The nightly is pinned deliberately.** `bpf-linker` has to agree with the LLVM version rustc emits bitcode for. A rolling nightly (LLVM 23.1.1 at the time of writing) produced bitcode `bpf-linker` couldn't parse — `ERROR llvm: Invalid record`. The pinned nightly carries LLVM 22.1.6, matching the system toolchain. `nazar-agent/build.rs` passes this toolchain explicitly via `Toolchain::Custom`.

### Without root

```bash
sudo setcap cap_bpf,cap_perfmon,cap_net_admin,cap_dac_read_search+eip ./target/debug/nazar-agent
./target/debug/nazar-agent
```

`cap_bpf,cap_perfmon,cap_net_admin` alone is **not** sufficient, and the reason is instructive: aya resolves tracepoint IDs by reading `/sys/kernel/tracing/events/<category>/<name>/id`, and tracefs is `drwx------ root:root` on most distributions. The attach fails with `tracefs not found` — not because tracefs is missing, but because the process can't enter the directory. Capability checks and file permissions are separate mechanisms that don't know about each other.

`cap_dac_read_search` closes that gap, at the cost of a capability that can read any file on the system. That is a real trade-off, not a free win.

One gap remains even then: reading `/proc/<pid>/exe` for a process owned by another user needs `CAP_SYS_PTRACE`. Without it the `/proc` seed leaves those entries empty and ancestry falls back to `comm`, so a chain shows `sddm-helper` rather than `/usr/lib/sddm/sddm-helper`. Partial visibility is the honest price of not running as root.

Note that `setcap` lives in the file's extended attributes, so it has to be reapplied after every `cargo build`.

### As a service

```bash
sudo install -Dm755 target/debug/nazar-agent /usr/local/bin/nazar-agent
sudo setcap cap_bpf,cap_perfmon,cap_net_admin,cap_dac_read_search+eip /usr/local/bin/nazar-agent
sudo install -Dm644 nazar-agent/rules.toml /etc/nazar/rules.toml
sudo install -Dm644 nazar.service /etc/systemd/system/nazar.service
sudo systemctl daemon-reload
sudo systemctl start nazar
journalctl -u nazar -f
```

The unit runs with ambient capabilities rather than as root, `NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute` and a restricted namespace set. `ProtectControlGroups` has to stay off — the `cgroup/connect` programs attach to `/sys/fs/cgroup`.

`systemctl stop` is handled: the agent catches SIGTERM, prints its drop report and deactivates cleanly.

---

## Design notes

Things that turned out to matter, and why.

### Filter in the kernel, cheapest check first

Unfiltered `openat` ran at **1085 events/sec** on a desktop — and the first forty samples were the agent's own `/proc` scan, so the sensor was largely observing itself. Three filters, ordered so the expensive one rarely runs:

1. skip our own tgid (one compare)
2. skip read-only opens — `flags & (O_WRONLY|O_RDWR|O_CREAT|O_TRUNC) == 0` (one mask)
3. only then read the path with `bpf_probe_read_user_str`

Result: **1085/sec → 2/sec**, and what remains is real (sqlite journals, IDE index writes, `/dev/shm` segments). Self-filtering also closes a feedback path: if the agent ever logs to a file, its own writes would otherwise generate events.

### Process identity has to survive PID reuse

Nodes are keyed `(tgid, start_time)`, not `tgid`. PIDs recycle; on a busy box the counter can wrap in hours. Without `start_time`, a dead process's record gets overwritten by an unrelated one and ancestry walks land on the wrong parent.

`start_time` comes from `task_struct.start_boottime`, read per event.

### Manual CO-RE

`aya` 0.14 / `aya-ebpf` 0.2 expose no CO-RE field relocation, and `aya-obj`'s BTF types are `pub(crate)`, so offsets can't be queried through the public API. `nazar-agent/src/btf.rs` parses `/sys/kernel/btf/vmlinux` directly — header, type-section walk with per-kind extra-data sizing, string section, struct member offsets — and `kernel_field_offset(struct, field)` is the reusable entry point.

The offset is resolved at load time and handed to the programs through an array map, rather than being baked in at compile time. That costs one lookup per event but needs no relocation support in the loader, and the same binary works across kernels with different layouts.

It paid for itself twice: `task_struct.start_boottime` → byte 3224 for the process key, and `linux_binprm.filename` → byte 112 for the LSM hook. Both verified against `bpftool`.

### Three tracepoints, three different shapes

The `sched_*` tracepoints don't agree on how they encode strings:

- `sched_process_exec`: `filename` is `__data_loc` — a `u32` where the **low** 16 bits are the offset into the tracepoint buffer and the **high** 16 bits are the length
- `sched_process_exit`: `comm` is an inline `char[16]`
- `sys_enter_execve`: `filename` is a raw userspace pointer, needs `bpf_probe_read_user_str`

The `__data_loc` layout was established by dumping the raw buffer, not by reading the format file — the format file tells you where the `u32` lives, not how it's packed.

### `group_dead` is not optional

`sched_process_exit` fires per *thread*. `atuin` spawns ~11 tokio/sqlx threads and each emits an exit. Removing a process from the table on the first exit corrupts the tree; only `group_dead=1` marks the real death.

### Things the BPF target doesn't have

No libc, so no `memset` and no `memmove`. Both showed up as link failures from innocuous-looking Rust:

- `aya`'s `bpf_get_current_comm()` wrapper zero-initialises a local array → `memset`. Fixed by calling the raw helper with a pointer straight into the reserved ring-buffer slot.
- copying `[u32; 4]` (an IPv6 address) as a block → `memmove`. Fixed by writing word by word.

General rule: don't bulk-copy arrays or structs kernel-side.

Related: event structs must be sized to what the kernel actually writes. `ExecEvent.comm` was declared `[u8; 256]` while `bpf_get_current_comm` writes 16 — the remaining 240 bytes were never initialised, so residue from earlier ring-buffer records leaked to userspace on every exec.

### Verifier notes

- **Bounded loops need a provable bound.** `argv` is read with `for i in 0..MAX_ARGS`; an unbounded `while ptr != null` is rejected.
- **Runtime offsets need masking.** Writing args into a flat buffer at a runtime cursor is unprovable on its own; `cursor & (ARGS_LEN - 1)` makes the range provable from the bit operation. `ARGS_LEN` must stay a power of two.
- **Context access is validated per attach type.** A shared helper reading both `user_ip4` and `user_ip6` is rejected in a `connect4` program (`invalid bpf_context access off=8 size=4`). `connect4` and `connect6` need separate bodies.

### A rule has to be discriminating, not just suspicious

"Exec from `$HOME`" sounds like a detection. On a developer desktop, JetBrains runs `jspawnhelper` and friends out of `~/.local/share` continuously, so the rule buries real hits. Requiring the basename to be a known *system command* keeps that quiet while still catching a binary planted to shadow the real one on `PATH`.

Same reason `not` blocks exist in the rule schema: loopback chatter was drowning the connection rules before `dst_ip` exclusions were added.

### Drop accounting

`reserve` failures increment a counter rather than failing silently, and the count is reported at shutdown. Without it there is no way to distinguish "nothing happened" from "the sensor was blind". The counter is a plain read-modify-write, not atomic — two CPUs incrementing concurrently can lose one — which is fine for an indicator and cheaper than a per-CPU map.

Measured: 4374 events at 104/sec, zero drops with the 1 MiB buffer.

---

## Known gaps

See [KNOWN_GAPS.md](KNOWN_GAPS.md) for what this sensor cannot see and why — io_uring, tampering, ring buffer flooding, and the rest. Building the sensor is how you learn where its coverage ends.

---

## Layout

```
nazar-agent/     userspace: loader, process table, BTF parser, rule engine
  src/btf.rs        /sys/kernel/btf/vmlinux parser
  src/procfs.rs     /proc snapshot for cold start
  src/proc_table.rs process tree, keyed (tgid, start_time)
  src/rules.rs      rule types + matching
  src/detect.rs     engine, correlation state, alerts
  rules.toml        detection rules
nazar-common/    #[repr(C)] event structs shared across the boundary
nazar-ebpf/      kernel-side programs (no_std, bpfel-unknown-none)
nazar.service    hardened systemd unit
```

`nazar-common` is the wire format. Both sides reinterpret the same bytes, so any change there has to land on both ends in lockstep.

---

## License

Userspace (`nazar-agent`, `nazar-common`) is dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

The kernel-side object (`nazar-ebpf`) declares `Dual MIT/GPL` in its ELF `license` section, and that declaration is load-bearing rather than ceremonial: the verifier refuses to load a program that calls a GPL-only helper unless the object claims a GPL-compatible license. `bpf_probe_read_kernel` and `bpf_probe_read_user_str` are both GPL-only, and the sensor cannot read a path or a `task_struct` field without them. [LICENSE-GPL2](LICENSE-GPL2) is included for that half.
