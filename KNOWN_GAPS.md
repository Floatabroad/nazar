# Known gaps

What `nazar` cannot see, and why. Building a sensor is the fastest way to learn where its coverage ends; this file is that knowledge written down rather than discovered by an attacker.

Each entry says what the gap is, why it exists, how hard it would be to close, and whether it is worth closing.

---

## 1. io_uring bypasses the syscall tracepoints

**The gap.** `nazar` hooks `sys_enter_openat` and `sys_enter_execve`. A process using io_uring submits file and network operations through a shared ring instead of individual syscalls — `IORING_OP_OPENAT`, `IORING_OP_READ`, `IORING_OP_CONNECT` and friends never pass through the syscall entry points these probes attach to.

**Why it exists.** io_uring is a batching interface: userspace writes submission queue entries and the kernel processes them from a worker context. The syscall boundary that tracepoints observe is `io_uring_enter`, which says "there is work" but not what the work is.

**Impact.** A file read or write performed through io_uring produces no `openat` event. The process still has to exec from somewhere, so exec-based rules keep working, but file-based detection is blind to it. This is an actively exploited technique, not a theoretical one — the class of "io_uring bypasses eBPF security tooling" findings is a few years old and still live.

**Closing it.** Hook `io_uring_submit_req` or the LSM hooks the operations eventually reach (`file_open` still fires for io_uring opens, since it is below the syscall layer). Moving the file probe from `sys_enter_openat` to `lsm/file_open` would close most of it — a good argument for doing more of the sensing at the LSM layer, which this project already has the machinery for.

**Worth it.** Yes. This is the most significant gap here.

---

## 2. The agent doesn't protect itself

**The gap.** Anything running as root can `kill` the agent, or detach its programs. The eBPF programs are not pinned, so when the process dies everything unloads and the machine goes dark.

**Why it exists.** Self-protection was never implemented; the agent is a plain process with no special standing.

**Impact.** Standard post-exploitation practice on a box with EDR is to identify and neutralise the sensor first. Here that costs one `kill`.

**Closing it.**
- Pin the programs and maps to bpffs so they survive the agent restarting.
- Use `lsm/task_kill` to deny signals targeting the agent's own pid.
- Use `lsm/bpf` to deny `BPF_PROG_DETACH` against the agent's own programs.

The third one is the interesting case: an LSM program defending its own attachment. It is also circular — whoever can load BPF can potentially unload that guard too — so it raises the cost rather than eliminating the possibility.

**Worth it.** Partly. Pinning is cheap and worth doing. Signal and detach guards are worth it for a production agent, less so for a learning project, but they are the natural next step for this codebase since the LSM plumbing already exists.

---

## 3. Ring buffer flooding

**The gap.** The ring buffer is 1 MiB. When `reserve` fails the event is dropped and a counter increments. An attacker who can generate event volume faster than userspace drains it can push a real event into the dropped set.

**Why it exists.** Any fixed-size buffer has this property. Under normal desktop load the measured rate was 104 events/sec with zero drops, so the headroom is large — but "large" is not "unbounded", and the attacker chooses the load.

**Impact.** The drop counter makes the flood *visible* (a spike in drops is itself a signal) but does not prevent the specific event from being lost. An attacker who floods for one second and acts in that second has a reasonable chance of the action going unrecorded.

**Closing it.** Fully, you can't. Mitigations:
- Per-CPU ring buffers, so one noisy CPU doesn't starve the others.
- Rate limiting per process kernel-side: a process producing thousands of events per second is itself suspicious and can be sampled rather than fully recorded.
- Treat a drop spike as a detection in its own right.

**Worth it.** The third one is nearly free and worth doing: a rule on the drop counter turns the evasion into a signal.

---

## 4. Cold start is approximate

**The gap.** Processes that existed before the agent attached are seeded from `/proc`. Their `start_time` comes from `/proc/<pid>/stat`, which reports in clock ticks (10 ms granularity), while the kernel reports `start_boottime` in nanoseconds. The two never match, so lookups fall back to newest-node-per-tgid.

**Why it exists.** `/proc` rounds. There is no interface that gives the exact value cheaply for every process.

**Impact.** Small but real. If a pre-existing process exits and its PID is reused during the fallback window, the wrong node can be resolved. On a busy machine that window is short but non-zero.

**Closing it.** Read `start_boottime` per process by other means at seed time (a BPF iterator over tasks, `bpf_iter`, would give exact values), or accept the approximation and document it — which is what happens now.

**Worth it.** A `bpf_iter` seed would be cleaner than `/proc` in every respect and is the right long-term answer.

---

## 5. The fork-to-first-event window

**The gap.** `fork` runs in the parent's context, so the child's `start_time` isn't knowable at fork time. The child gets a placeholder node keyed `(tgid, 0)`, promoted to its real key when its own first event arrives.

**Impact.** Between those two moments the child is tracked but not precisely identified. Actions in that window are attributed through the placeholder. A process that forks and does something interesting before its first observable event is recorded with less precision.

**Closing it.** `sched_process_fork` fires in the parent, but the child's `task_struct` is reachable from the tracepoint arguments on some kernels — reading `start_boottime` from it directly would remove the placeholder entirely.

**Worth it.** Yes, and it would simplify `proc_table.rs` noticeably.

---

## 6. Coverage holes in file operations

**The gap.** Only `openat` with write flags is observed. Not covered:

- `unlink` / `unlinkat` — log deletion, anti-forensics (T1070.004)
- `rename` / `renameat2` — the usual way a dropper lands a file atomically
- `chmod` / `fchmodat` — making a downloaded file executable (T1222)
- `link` / `symlink` — hardlink and symlink games
- Writes through an already-open fd — the open is seen, subsequent writes are not
- `openat2`, and `open` on kernels where it still exists

**Impact.** The "download, chmod +x, execute" chain is currently detected at the exec step, not at the chmod step. Deletion of logs is invisible.

**Closing it.** Each is another tracepoint or LSM hook with the same shape as the existing ones. `lsm/path_unlink`, `lsm/path_rename`, `lsm/path_chmod` would cover the first three at the semantic layer.

**Worth it.** Yes — this is the cheapest coverage improvement available, since the machinery is all there.

---

## 7. Enforcement is exact-match only

**The gap.** `EXEC_DENYLIST` is a hash map keyed on the full 256-byte path. Denying `/tmp/evil` does nothing about `/tmp/evil2`, a copy at a different path, or the same binary reached through a symlink or bind mount.

**Why it exists.** Hash maps do exact lookups. Prefix matching needs an LPM trie; content matching needs hashing the file.

**Impact.** As a demonstration of enforcement it is fine. As a policy mechanism it is trivially evaded by `cp`.

**Closing it.** An LPM trie for path prefixes, or — much stronger — denying by file hash rather than path, which survives renames and copies. The latter needs the hash computed somewhere and cached by inode.

**Worth it.** Path prefixes, yes. Hash-based policy is a project of its own.

---

## 8. Containers are not modelled

**The gap.** Events carry no container identity. A process inside a container looks like any other process, and its path is reported as seen from *its* mount namespace, not the host's.

**Impact.** On a container host, ancestry chains cross namespace boundaries without saying so, and identical paths in different containers are indistinguishable.

**Closing it.** `bpf_get_current_cgroup_id()` is one helper call and would attribute every event to a cgroup, which maps to a container. The `cgroup/connect` programs already run per-cgroup, so half the plumbing exists.

**Worth it.** Yes if the target is cloud-native (this is Tetragon's whole niche); not needed for a single-host agent.

---

## 9. Argv is captured, environment is not

**The gap.** `sys_enter_execve`'s third argument is `envp`, and it is ignored.

**Impact.** `LD_PRELOAD`, `LD_LIBRARY_PATH` and `LD_AUDIT` injection (T1574.006) are invisible. These are common enough that their absence is a real hole.

**Closing it.** The same bounded-loop pattern used for `argv`, applied to `envp`, filtered to the handful of variables worth recording. Recording the whole environment is a bad idea — it routinely contains credentials.

**Worth it.** Yes, for `LD_*` specifically.

---

## 10. What the ancestry chain doesn't tell you

**The gap.** The chain shows lineage, not causality. A process reparented to PID 1 after its parent died shows `systemd` as its parent, which is true and useless. Daemons that fork twice deliberately produce exactly this.

**Impact.** For a process whose parent exited before the alert, the chain is shorter and less informative than it appears. The tombstoning in `proc_table.rs` mitigates this — dead parents are kept while they still have children — but only for parents the agent actually observed.

**Closing it.** Not really closable; it is a property of the process model. Recording the *original* parent at fork time (which the table does) and surfacing it separately from the current parent would make the distinction explicit rather than silent.

**Worth it.** Cheap to do and worth it for alert quality.

---

## Notes on the ones that aren't gaps

Two things that look like gaps but aren't, worth stating so they don't get "fixed":

**argv tampering doesn't affect this sensor.** A process can rewrite its own `argv` after exec — systemd does exactly this, and `ps` shows the rewritten version. `nazar` captures argv at exec time from the kernel, before userspace can touch it. Observed directly: `systemd-userwork` appears in `ps` with a scrubbed command line, and as its real one here.

**The `exec` / `proc_exec` duplication is deliberate.** `sys_enter_execve` fires for every attempt including failures, `sched_process_exec` only for successes. Four `exec` events and one `proc_exec` for a single `ip` invocation is PATH resolution, not a bug — and the failed attempts are themselves informative, since they show what an attacker was looking for.
