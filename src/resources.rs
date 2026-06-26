//! Host resource sampling for the realtime monitor.
//!
//! A single shared collector reads `/proc` once per second and broadcasts one
//! [`ResourceSample`] to every connected viewer. Collection is demand-driven:
//! [`collect_tick`] skips reading `/proc` entirely when there are no subscribers
//! (see the loop in `main.rs`), so it costs nothing while nobody is watching and
//! its cost is independent of the number of viewers.
//!
//! The `/proc` parsers are pure functions (`&str` in, numbers out) so they are
//! unit-testable without touching the filesystem. The platform split lives
//! behind [`ResourceSampler`] / [`new_sampler`]: Linux reads `/proc`, every
//! other OS gets [`UnsupportedSampler`] which reports `supported: false` so the
//! frontend shows an "unsupported on this OS" notice. A Windows backend can be
//! added later by implementing the trait — nothing in the transport or frontend
//! changes.

use crate::model::now_ms;
use serde::Serialize;
use tokio::sync::broadcast;

/// One host-resource sample, broadcast to monitor clients once per second.
///
/// `cpu_percent` and the `*_bps` rates are deltas vs. the collector's previous
/// sample; on the first sample of an active session they are `0` (no prior point
/// to diff). `supported` is `true` for the Linux sampler and `false` for the
/// fallback. Derives `Default` so the fallback and tests can build a zeroed one;
/// `supported` therefore defaults to `false` and the Linux path sets it
/// explicitly.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ResourceSample {
    pub ts: i64,
    pub supported: bool,
    /// 0.0..=100.0 over the last interval; 0.0 on the first sample.
    pub cpu_percent: f64,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub mem_total_kb: u64,
    pub mem_available_kb: u64,
    pub mem_used_kb: u64,
    pub swap_total_kb: u64,
    pub swap_used_kb: u64,
    pub fd_allocated: u64,
    pub fd_max: u64,
    /// Aggregate bytes/sec, excludes `lo`.
    pub net_rx_bps: u64,
    pub net_tx_bps: u64,
    pub interfaces: Vec<IfaceStat>,
}

/// Per-interface throughput, ifstat-style.
#[derive(Debug, Clone, Serialize)]
pub struct IfaceStat {
    pub name: String,
    /// Bytes/sec since the previous sample (0 on the first).
    pub rx_bps: u64,
    pub tx_bps: u64,
    /// Cumulative bytes from `/proc/net/dev`.
    pub rx_total: u64,
    pub tx_total: u64,
}

/// Produces one host-resource snapshot. Stateful: holds the previous raw
/// counters so it can compute CPU% and per-interface byte rates.
pub trait ResourceSampler: Send {
    /// Take a sample. `dt_secs` is the wall time since the previous call (the
    /// ticker interval), used to convert byte deltas to per-second rates.
    fn sample(&mut self, dt_secs: f64) -> ResourceSample;
    /// Forget previous counters so the next `sample` re-initialises its
    /// baseline. Called when the viewer count drops to zero, so a stale gap is
    /// never turned into a huge bogus rate when a viewer reconnects later.
    fn reset(&mut self);
}

/// Construct the platform-appropriate sampler. `#[cfg]`-selected so callers
/// never see the split.
#[cfg(target_os = "linux")]
pub fn new_sampler() -> Box<dyn ResourceSampler> {
    Box::new(LinuxSampler::default())
}

#[cfg(target_os = "windows")]
pub fn new_sampler() -> Box<dyn ResourceSampler> {
    Box::new(windows_impl::WindowsSampler::default())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn new_sampler() -> Box<dyn ResourceSampler> {
    Box::new(UnsupportedSampler)
}

/// Fallback sampler for platforms without a backend (not Linux or Windows):
/// always reports `supported: false`. Kept available under `test` so the unit
/// test can exercise it on any host.
#[cfg(any(test, not(any(target_os = "linux", target_os = "windows"))))]
pub struct UnsupportedSampler;

#[cfg(any(test, not(any(target_os = "linux", target_os = "windows"))))]
impl ResourceSampler for UnsupportedSampler {
    fn sample(&mut self, _dt_secs: f64) -> ResourceSample {
        ResourceSample {
            ts: now_ms(),
            supported: false,
            ..Default::default()
        }
    }
    fn reset(&mut self) {}
}

// ---------------------------------------------------------------------------
// Pure `/proc` parsers (testable without any filesystem access). Only the Linux
// sampler and the tests use them, so they are cfg-gated to keep non-Linux
// (e.g. the Windows dev box) builds warning-free.
// ---------------------------------------------------------------------------

/// Aggregate CPU time counters (jiffies on Linux, 100ns ticks on Windows).
#[cfg(any(target_os = "linux", target_os = "windows", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpuTimes {
    /// idle + iowait
    idle: u64,
    /// sum of every numeric field on the `cpu` line
    total: u64,
}

/// Cumulative byte counters for one interface.
#[cfg(any(target_os = "linux", target_os = "windows", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IfaceCounters {
    rx: u64,
    tx: u64,
}

/// Parse the aggregate `cpu` line of `/proc/stat`.
///
/// Sums **all** whitespace-separated integer fields after the `cpu` label (not a
/// fixed count — kernels add fields over time: `steal`, `guest`, `guest_nice`).
/// `idle` is `idle + iowait` (fields 3 and 4). Any field that fails to parse as
/// `u64` ends the numeric run.
#[cfg(any(target_os = "linux", test))]
fn parse_cpu_times(stat: &str) -> Option<CpuTimes> {
    // The aggregate line starts with "cpu " (two spaces in the file); per-core
    // lines are "cpu0", "cpu1", … and must be skipped.
    let line = stat
        .lines()
        .find(|l| l.starts_with("cpu ") || l.trim_end() == "cpu")?;
    let nums: Vec<u64> = line
        .split_whitespace()
        .skip(1) // the "cpu" label
        .map_while(|t| t.parse::<u64>().ok())
        .collect();
    if nums.is_empty() {
        return None;
    }
    let idle = nums.get(3).copied().unwrap_or(0);
    let iowait = nums.get(4).copied().unwrap_or(0);
    let total: u64 = nums.iter().sum();
    Some(CpuTimes {
        idle: idle.saturating_add(iowait),
        total,
    })
}

/// CPU busy-% from two successive `CpuTimes`. Returns 0.0 when there is no usable
/// interval (`dt_secs <= 0`) or the time delta is zero. Clamped to 0.0..=100.0.
#[cfg(any(target_os = "linux", target_os = "windows", test))]
fn cpu_percent(prev: &CpuTimes, cur: &CpuTimes, dt_secs: f64) -> f64 {
    if dt_secs <= 0.0 {
        return 0.0;
    }
    let total_delta = cur.total.saturating_sub(prev.total);
    if total_delta == 0 {
        return 0.0;
    }
    let idle_delta = cur.idle.saturating_sub(prev.idle);
    let busy = total_delta.saturating_sub(idle_delta);
    let pct = 100.0 * (busy as f64) / (total_delta as f64);
    pct.clamp(0.0, 100.0)
}

/// Build a [`CpuTimes`] from Windows `GetSystemTimes` 100ns-tick totals. On
/// Windows `kernel` already includes `idle`, so total busy+idle time is
/// `kernel + user` and `idle` passes through unchanged — matching the
/// `(total, idle)` convention `cpu_percent` expects. Pure → unit-testable
/// without touching the OS.
#[cfg(any(target_os = "windows", test))]
fn cpu_times_from_filetimes(idle: u64, kernel: u64, user: u64) -> CpuTimes {
    CpuTimes {
        idle,
        total: kernel.saturating_add(user),
    }
}

/// Memory totals (kB) parsed from `/proc/meminfo`.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Meminfo {
    mem_total_kb: u64,
    mem_available_kb: u64,
    mem_used_kb: u64,
    swap_total_kb: u64,
    swap_used_kb: u64,
}

/// Parse the handful of `/proc/meminfo` keys we display. Missing keys default to
/// 0 (a kernel without `MemAvailable` then reports `used == total`).
#[cfg(any(target_os = "linux", test))]
fn parse_meminfo(s: &str) -> Meminfo {
    let mut total = 0;
    let mut avail = 0;
    let mut swap_total = 0;
    let mut swap_free = 0;
    for line in s.lines() {
        // "MemTotal:       16331156 kB" — key before ':', value is the next token.
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let val = rest.split_whitespace().next().and_then(|t| t.parse::<u64>().ok());
        let Some(val) = val else { continue };
        match key.trim() {
            "MemTotal" => total = val,
            "MemAvailable" => avail = val,
            "SwapTotal" => swap_total = val,
            "SwapFree" => swap_free = val,
            _ => {}
        }
    }
    Meminfo {
        mem_total_kb: total,
        mem_available_kb: avail,
        mem_used_kb: total.saturating_sub(avail),
        swap_total_kb: swap_total,
        swap_used_kb: swap_total.saturating_sub(swap_free),
    }
}

/// Parse `/proc/sys/fs/file-nr` → `(allocated, max)` (fields 1 and 3; the middle
/// "unused" field is ignored). Returns `(0, 0)` on a malformed line.
#[cfg(any(target_os = "linux", test))]
fn parse_file_nr(s: &str) -> (u64, u64) {
    let mut it = s.split_whitespace();
    let allocated = it.next().and_then(|t| t.parse::<u64>().ok());
    let _unused = it.next();
    let max = it.next().and_then(|t| t.parse::<u64>().ok());
    match (allocated, max) {
        (Some(a), Some(m)) => (a, m),
        _ => (0, 0),
    }
}

/// Parse the three load averages from `/proc/loadavg` (instantaneous; no diff).
/// Missing/garbage fields default to 0.0.
#[cfg(any(target_os = "linux", test))]
fn parse_loadavg(s: &str) -> (f64, f64, f64) {
    let mut it = s.split_whitespace();
    let p = |t: Option<&str>| t.and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0);
    (p(it.next()), p(it.next()), p(it.next()))
}

/// Parse `/proc/net/dev` into `(name, counters)` per interface.
///
/// Each data line is `  iface: rxbytes rxpackets ... txbytes txpackets ...`.
/// Split on the **first** `:` first (the name is everything before it), then
/// whitespace-tokenise the remainder — a wide rx count can abut the colon with
/// no space (`enp0s31f6:12345`). Column 0 after the colon is `rx_bytes`,
/// column 8 is `tx_bytes` (standard layout). The two header lines have no `:` in
/// a position that yields numeric columns and are skipped naturally.
#[cfg(any(target_os = "linux", test))]
fn parse_net_dev(s: &str) -> Vec<(String, IfaceCounters)> {
    let mut out = Vec::new();
    for line in s.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() || name.contains('|') {
            continue; // header line ("Inter-|   Receive ...")
        }
        let cols: Vec<u64> = rest
            .split_whitespace()
            .map(|t| t.parse::<u64>().unwrap_or(0))
            .collect();
        // Need at least rx_bytes (0) and tx_bytes (8).
        if cols.len() < 9 {
            continue;
        }
        out.push((
            name.to_string(),
            IfaceCounters {
                rx: cols[0],
                tx: cols[8],
            },
        ));
    }
    out
}

/// Bytes/sec from two cumulative counters. Returns 0 on a counter reset
/// (`cur < prev`, interface re-created / wrapped) or no usable interval.
#[cfg(any(target_os = "linux", target_os = "windows", test))]
fn rate(prev: u64, cur: u64, dt_secs: f64) -> u64 {
    if dt_secs <= 0.0 || cur < prev {
        return 0;
    }
    ((cur - prev) as f64 / dt_secs) as u64
}

// ---------------------------------------------------------------------------
// Linux sampler
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[derive(Default)]
pub struct LinuxSampler {
    prev_cpu: Option<CpuTimes>,
    prev_net: Option<std::collections::HashMap<String, IfaceCounters>>,
}

#[cfg(target_os = "linux")]
impl ResourceSampler for LinuxSampler {
    fn sample(&mut self, dt_secs: f64) -> ResourceSample {
        use std::fs::read_to_string;

        let stat = read_to_string("/proc/stat").unwrap_or_default();
        let meminfo = read_to_string("/proc/meminfo").unwrap_or_default();
        let file_nr = read_to_string("/proc/sys/fs/file-nr").unwrap_or_default();
        let loadavg = read_to_string("/proc/loadavg").unwrap_or_default();
        let net_dev = read_to_string("/proc/net/dev").unwrap_or_default();

        // CPU.
        let cur_cpu = parse_cpu_times(&stat);
        let cpu_pct = match (self.prev_cpu, cur_cpu) {
            (Some(prev), Some(cur)) => cpu_percent(&prev, &cur, dt_secs),
            _ => 0.0,
        };
        self.prev_cpu = cur_cpu;

        // Memory + fd + load.
        let mem = parse_meminfo(&meminfo);
        let (fd_allocated, fd_max) = parse_file_nr(&file_nr);
        let (load1, load5, load15) = parse_loadavg(&loadavg);

        // Network: per-interface rates vs. the previous sample.
        let cur_net = parse_net_dev(&net_dev);
        let prev_net = self.prev_net.take();
        let mut interfaces: Vec<IfaceStat> = Vec::with_capacity(cur_net.len());
        let mut agg_rx: u64 = 0;
        let mut agg_tx: u64 = 0;
        let mut next_net = std::collections::HashMap::with_capacity(cur_net.len());
        for (name, cur) in &cur_net {
            let prev = prev_net.as_ref().and_then(|m| m.get(name));
            let (rx_bps, tx_bps) = match prev {
                Some(p) => (rate(p.rx, cur.rx, dt_secs), rate(p.tx, cur.tx, dt_secs)),
                None => (0, 0),
            };
            // Aggregate excludes loopback (would double-count local traffic).
            if name != "lo" {
                agg_rx = agg_rx.saturating_add(rx_bps);
                agg_tx = agg_tx.saturating_add(tx_bps);
            }
            interfaces.push(IfaceStat {
                name: name.clone(),
                rx_bps,
                tx_bps,
                rx_total: cur.rx,
                tx_total: cur.tx,
            });
            next_net.insert(name.clone(), *cur);
        }
        self.prev_net = Some(next_net);
        // Busiest links first, then by name — helps when there are many veth*.
        interfaces.sort_by(|a, b| {
            (b.rx_bps + b.tx_bps)
                .cmp(&(a.rx_bps + a.tx_bps))
                .then_with(|| a.name.cmp(&b.name))
        });

        ResourceSample {
            ts: now_ms(),
            supported: true,
            cpu_percent: cpu_pct,
            load1,
            load5,
            load15,
            mem_total_kb: mem.mem_total_kb,
            mem_available_kb: mem.mem_available_kb,
            mem_used_kb: mem.mem_used_kb,
            swap_total_kb: mem.swap_total_kb,
            swap_used_kb: mem.swap_used_kb,
            fd_allocated,
            fd_max,
            net_rx_bps: agg_rx,
            net_tx_bps: agg_tx,
            interfaces,
        }
    }

    fn reset(&mut self) {
        self.prev_cpu = None;
        self.prev_net = None;
    }
}

// ---------------------------------------------------------------------------
// Windows sampler — documented Win32 calls, no /proc and no runtime cost.
// CPU: GetSystemTimes, RAM: GlobalMemoryStatusEx, handles (fd analogue):
// GetPerformanceInfo, per-interface bytes: GetIfTable2. Load average has no
// Windows equivalent (reported as 0).
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::{
        CpuTimes, IfaceCounters, IfaceStat, ResourceSample, ResourceSampler, cpu_percent,
        cpu_times_from_filetimes, now_ms, rate,
    };
    use std::collections::HashMap;
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2};
    use windows_sys::Win32::System::ProcessStatus::{GetPerformanceInfo, PERFORMANCE_INFORMATION};
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    use windows_sys::Win32::System::Threading::GetSystemTimes;

    /// IF_TYPE_SOFTWARE_LOOPBACK — excluded from the aggregate throughput.
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    /// IfOperStatusUp — only operational interfaces are listed (Windows reports
    /// dozens of dead tunnel/pseudo-adapters otherwise).
    const IF_OPER_STATUS_UP: i32 = 1;
    /// `FilterInterface` bit (bit 1) of `InterfaceAndOperStatusFlags`. Windows
    /// stacks an NDIS filter pseudo-interface (QoS Packet Scheduler, WFP MAC
    /// filters, LightWeight Filters) on top of every real NIC; they duplicate
    /// the real interface and are skipped.
    const FILTER_INTERFACE_BIT: u8 = 0x02;

    #[derive(Default)]
    pub struct WindowsSampler {
        prev_cpu: Option<CpuTimes>,
        prev_net: Option<HashMap<String, IfaceCounters>>,
    }

    fn filetime_to_u64(ft: &FILETIME) -> u64 {
        ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
    }

    fn read_cpu() -> Option<CpuTimes> {
        // SAFETY: three out-params; GetSystemTimes fully writes each FILETIME.
        unsafe {
            let mut idle: FILETIME = std::mem::zeroed();
            let mut kernel: FILETIME = std::mem::zeroed();
            let mut user: FILETIME = std::mem::zeroed();
            if GetSystemTimes(&mut idle, &mut kernel, &mut user) == 0 {
                return None;
            }
            Some(cpu_times_from_filetimes(
                filetime_to_u64(&idle),
                filetime_to_u64(&kernel),
                filetime_to_u64(&user),
            ))
        }
    }

    /// (total_kb, available_kb, used_kb)
    fn read_mem() -> (u64, u64, u64) {
        // SAFETY: dwLength set to the struct size before the call, as required.
        unsafe {
            let mut m: MEMORYSTATUSEX = std::mem::zeroed();
            m.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
            if GlobalMemoryStatusEx(&mut m) == 0 {
                return (0, 0, 0);
            }
            let total = m.ullTotalPhys / 1024;
            let avail = m.ullAvailPhys / 1024;
            (total, avail, total.saturating_sub(avail))
        }
    }

    /// System-wide open handle count — the Windows analogue of open fds.
    fn read_handles() -> u64 {
        // SAFETY: cb set to the struct size as required.
        unsafe {
            let mut pi: PERFORMANCE_INFORMATION = std::mem::zeroed();
            let cb = std::mem::size_of::<PERFORMANCE_INFORMATION>() as u32;
            pi.cb = cb;
            if GetPerformanceInfo(&mut pi, cb) == 0 {
                return 0;
            }
            pi.HandleCount as u64
        }
    }

    /// Per-interface cumulative byte counters: (name, counters, is_loopback).
    fn read_net() -> Vec<(String, IfaceCounters, bool)> {
        // SAFETY: GetIfTable2 allocates the table; we read NumEntries rows from
        // the flexible array, then FreeMibTable it. All pointers come from the API.
        unsafe {
            let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
            if GetIfTable2(&mut table) != 0 || table.is_null() {
                return Vec::new();
            }
            let n = (*table).NumEntries as usize;
            let rows = (*table).Table.as_ptr();
            let mut out = Vec::with_capacity(n);
            for i in 0..n {
                let row = &*rows.add(i);
                // Skip non-operational adapters (Windows lists many dead ones)
                // and the NDIS filter pseudo-interfaces layered on real NICs.
                if row.OperStatus != IF_OPER_STATUS_UP
                    || row.InterfaceAndOperStatusFlags._bitfield & FILTER_INTERFACE_BIT != 0
                {
                    continue;
                }
                let alias = &row.Alias;
                let len = alias.iter().position(|&c| c == 0).unwrap_or(alias.len());
                let name = String::from_utf16_lossy(&alias[..len]);
                out.push((
                    name,
                    IfaceCounters { rx: row.InOctets, tx: row.OutOctets },
                    row.Type == IF_TYPE_SOFTWARE_LOOPBACK,
                ));
            }
            FreeMibTable(table as *const core::ffi::c_void);
            out
        }
    }

    impl ResourceSampler for WindowsSampler {
        fn sample(&mut self, dt_secs: f64) -> ResourceSample {
            let cur_cpu = read_cpu();
            let cpu_pct = match (self.prev_cpu, cur_cpu) {
                (Some(prev), Some(cur)) => cpu_percent(&prev, &cur, dt_secs),
                _ => 0.0,
            };
            self.prev_cpu = cur_cpu;

            let (mem_total_kb, mem_available_kb, mem_used_kb) = read_mem();
            let fd_allocated = read_handles();

            let cur_net = read_net();
            let prev_net = self.prev_net.take();
            let mut interfaces: Vec<IfaceStat> = Vec::with_capacity(cur_net.len());
            let mut agg_rx = 0u64;
            let mut agg_tx = 0u64;
            let mut next_net = HashMap::with_capacity(cur_net.len());
            for (name, cur, is_loopback) in &cur_net {
                let prev = prev_net.as_ref().and_then(|m| m.get(name));
                let (rx_bps, tx_bps) = match prev {
                    Some(p) => (rate(p.rx, cur.rx, dt_secs), rate(p.tx, cur.tx, dt_secs)),
                    None => (0, 0),
                };
                if !is_loopback {
                    agg_rx = agg_rx.saturating_add(rx_bps);
                    agg_tx = agg_tx.saturating_add(tx_bps);
                }
                interfaces.push(IfaceStat {
                    name: name.clone(),
                    rx_bps,
                    tx_bps,
                    rx_total: cur.rx,
                    tx_total: cur.tx,
                });
                next_net.insert(name.clone(), *cur);
            }
            self.prev_net = Some(next_net);
            interfaces.sort_by(|a, b| {
                (b.rx_bps + b.tx_bps)
                    .cmp(&(a.rx_bps + a.tx_bps))
                    .then_with(|| a.name.cmp(&b.name))
            });

            ResourceSample {
                ts: now_ms(),
                supported: true,
                cpu_percent: cpu_pct,
                load1: 0.0,
                load5: 0.0,
                load15: 0.0,
                mem_total_kb,
                mem_available_kb,
                mem_used_kb,
                // Pagefile is a commit limit, not a swap area, so reporting it as
                // "swap" would mislead; report 0 (the frontend then hides swap).
                swap_total_kb: 0,
                swap_used_kb: 0,
                fd_allocated,
                fd_max: 0, // no hard limit → frontend shows ∞ and auto-scales
                net_rx_bps: agg_rx,
                net_tx_bps: agg_tx,
                interfaces,
            }
        }

        fn reset(&mut self) {
            self.prev_cpu = None;
            self.prev_net = None;
        }
    }
}

// ---------------------------------------------------------------------------
// Collector tick (demand-driven; called once per second from main.rs)
// ---------------------------------------------------------------------------

/// One collector tick. Reads and broadcasts a sample only while there is at
/// least one subscriber; on the falling edge to zero viewers it resets the
/// sampler's baseline (once) so a later reconnect after a long idle gap does not
/// produce a giant bogus rate. `active` tracks whether viewers were present on
/// the previous tick.
///
/// A mid-stream second viewer does **not** reset the baseline (only the falling
/// edge to zero does), so a late joiner's first received sample already carries
/// real non-zero rates from the already-active collector; only the very first
/// viewer after an idle period sees a 0-rate first sample.
pub fn collect_tick(
    sampler: &mut dyn ResourceSampler,
    sender: &broadcast::Sender<ResourceSample>,
    active: &mut bool,
) {
    if sender.receiver_count() == 0 {
        if *active {
            sampler.reset();
            *active = false;
        }
        return; // no viewers → do not read /proc
    }
    *active = true;
    let sample = sampler.sample(1.0); // dt = the 1 s tick interval
    let _ = sender.send(sample); // ignore: no-op if all receivers just dropped
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_times_sums_all_fields_and_idle_is_idle_plus_iowait() {
        // user nice system idle iowait irq softirq steal guest guest_nice
        let stat = "cpu  100 0 50 800 40 10 0 0 0 0\ncpu0 50 0 25 400 20 5 0 0 0 0\n";
        let t = parse_cpu_times(stat).unwrap();
        assert_eq!(t.idle, 840); // 800 + 40
        assert_eq!(t.total, 100 + 0 + 50 + 800 + 40 + 10 + 0 + 0 + 0 + 0);
    }

    #[test]
    fn cpu_percent_from_two_samples() {
        let prev = CpuTimes { idle: 800, total: 1000 };
        // 100 more total, 60 of it idle → 40 busy of 100 → 40%.
        let cur = CpuTimes { idle: 860, total: 1100 };
        assert!((cpu_percent(&prev, &cur, 1.0) - 40.0).abs() < 1e-9);
    }

    #[test]
    fn cpu_percent_guards_zero_denominator_and_dt_and_clamps() {
        let p = CpuTimes { idle: 10, total: 100 };
        // No total movement → 0, not NaN.
        assert_eq!(cpu_percent(&p, &p, 1.0), 0.0);
        // dt <= 0 → 0.
        let cur = CpuTimes { idle: 10, total: 200 };
        assert_eq!(cpu_percent(&p, &cur, 0.0), 0.0);
        // Idle going backwards can't push busy over 100%.
        let cur2 = CpuTimes { idle: 5, total: 200 };
        assert!(cpu_percent(&p, &cur2, 1.0) <= 100.0);
    }

    #[test]
    fn meminfo_parses_used_and_swap() {
        let s = "\
MemTotal:       16000 kB
MemFree:         2000 kB
MemAvailable:    9000 kB
SwapTotal:       4000 kB
SwapFree:        1000 kB
";
        let m = parse_meminfo(s);
        assert_eq!(m.mem_total_kb, 16000);
        assert_eq!(m.mem_available_kb, 9000);
        assert_eq!(m.mem_used_kb, 7000); // 16000 - 9000
        assert_eq!(m.swap_total_kb, 4000);
        assert_eq!(m.swap_used_kb, 3000); // 4000 - 1000
    }

    #[test]
    fn meminfo_missing_available_does_not_panic() {
        let s = "MemTotal:  16000 kB\nMemFree:  2000 kB\n";
        let m = parse_meminfo(s);
        assert_eq!(m.mem_total_kb, 16000);
        assert_eq!(m.mem_available_kb, 0);
        assert_eq!(m.mem_used_kb, 16000); // used == total when avail unknown
    }

    #[test]
    fn file_nr_parses_allocated_and_max() {
        assert_eq!(
            parse_file_nr("19360\t0\t9223372036854775807"),
            (19360, 9223372036854775807)
        );
        assert_eq!(parse_file_nr("garbage"), (0, 0));
        assert_eq!(parse_file_nr(""), (0, 0));
    }

    #[test]
    fn loadavg_parses_three_fields() {
        assert_eq!(parse_loadavg("0.52 0.58 0.59 1/834 12345"), (0.52, 0.58, 0.59));
        assert_eq!(parse_loadavg(""), (0.0, 0.0, 0.0));
        assert_eq!(parse_loadavg("garbage here too"), (0.0, 0.0, 0.0));
    }

    fn net_dev_fixture(eth_rx: u64, eth_tx: u64) -> String {
        format!(
            "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0
  eth0: {eth_rx} 100 0 0 0 0 0 0 {eth_tx} 80 0 0 0 0 0 0
"
        )
    }

    #[test]
    fn net_dev_parses_interfaces_and_columns() {
        let parsed = parse_net_dev(&net_dev_fixture(5000, 3000));
        let map: std::collections::HashMap<_, _> = parsed.into_iter().collect();
        assert_eq!(map["lo"], IfaceCounters { rx: 1000, tx: 2000 });
        assert_eq!(map["eth0"], IfaceCounters { rx: 5000, tx: 3000 });
    }

    #[test]
    fn net_dev_handles_name_abutting_colon() {
        let line = "enp0s31f6:123456789 100 0 0 0 0 0 0 987654321 80 0 0 0 0 0 0\n";
        let parsed = parse_net_dev(line);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0, "enp0s31f6");
        assert_eq!(parsed[0].1, IfaceCounters { rx: 123456789, tx: 987654321 });
    }

    #[test]
    fn rate_normal_reset_and_dt_guards() {
        assert_eq!(rate(1000, 3000, 1.0), 2000); // 2000 bytes in 1 s
        assert_eq!(rate(1000, 5000, 2.0), 2000); // 4000 bytes over 2 s
        assert_eq!(rate(5000, 1000, 1.0), 0); // counter reset → 0
        assert_eq!(rate(1000, 3000, 0.0), 0); // dt <= 0 → 0
    }

    #[test]
    fn windows_cpu_times_total_is_kernel_plus_user_and_percent_is_correct() {
        // On Windows `kernel` already includes `idle`; total = kernel + user.
        let prev = cpu_times_from_filetimes(100, 300, 50); // idle 100, total 350
        assert_eq!(prev.idle, 100);
        assert_eq!(prev.total, 350);
        // +60 idle, +150 total → 90 busy of 150 → 60%.
        let cur = cpu_times_from_filetimes(160, 400, 100); // idle 160, total 500
        assert!((cpu_percent(&prev, &cur, 1.0) - 60.0).abs() < 1e-9);
    }

    #[test]
    fn unsupported_sampler_reports_unsupported_and_zeros() {
        let mut s = UnsupportedSampler;
        let sample = s.sample(1.0);
        assert!(!sample.supported);
        assert_eq!(sample.cpu_percent, 0.0);
        assert_eq!(sample.mem_total_kb, 0);
        assert!(sample.interfaces.is_empty());
    }

    /// A fake sampler that records how many times `reset`/`sample` were called,
    /// so we can drive `collect_tick` and assert the demand-driven gating and the
    /// falling-edge reset without any real `/proc` or sockets.
    #[derive(Default)]
    struct FakeSampler {
        samples: u32,
        resets: u32,
    }
    impl ResourceSampler for FakeSampler {
        fn sample(&mut self, _dt: f64) -> ResourceSample {
            self.samples += 1;
            ResourceSample { supported: true, ..Default::default() }
        }
        fn reset(&mut self) {
            self.resets += 1;
        }
    }

    #[test]
    fn collect_tick_is_demand_driven_and_resets_on_falling_edge() {
        let (tx, _) = broadcast::channel::<ResourceSample>(8);
        let mut sampler = FakeSampler::default();
        let mut active = false;

        // No subscribers: never samples, never resets (was not active).
        collect_tick(&mut sampler, &tx, &mut active);
        assert_eq!(sampler.samples, 0);
        assert_eq!(sampler.resets, 0);
        assert!(!active);

        // A viewer subscribes → receiver_count() == 1 immediately.
        let mut rx = tx.subscribe();
        collect_tick(&mut sampler, &tx, &mut active);
        assert_eq!(sampler.samples, 1);
        assert!(active);
        assert!(rx.try_recv().is_ok()); // the sample was broadcast

        // A second viewer mid-stream must NOT reset the baseline.
        let _rx2 = tx.subscribe();
        collect_tick(&mut sampler, &tx, &mut active);
        assert_eq!(sampler.samples, 2);
        assert_eq!(sampler.resets, 0);

        // All viewers leave → falling edge resets exactly once.
        drop(rx);
        drop(_rx2);
        collect_tick(&mut sampler, &tx, &mut active);
        assert_eq!(sampler.resets, 1);
        assert!(!active);
        assert_eq!(sampler.samples, 2); // did not sample with zero viewers

        // Still zero viewers → no second reset.
        collect_tick(&mut sampler, &tx, &mut active);
        assert_eq!(sampler.resets, 1);
    }
}
