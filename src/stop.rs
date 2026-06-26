//! `sn-proxy stop` — terminate every running sn-proxy process.
//!
//! Detached daemons are spawned with no console and only the most recently
//! started pid is recorded in the pidfile, so a pidfile-only stop would leak
//! orphaned instances. Instead this enumerates every live process whose
//! executable basename matches the current binary (e.g. `sn-proxy.exe` on
//! Windows, `sn-proxy` on Unix), skips the pid of the process running the stop
//! command itself, and force-terminates the rest. The daemon pidfile is then
//! removed best-effort.
//!
//! Termination is forceful on both platforms (Windows `TerminateProcess`,
//! Unix `SIGKILL`). The server installs no signal/graceful-shutdown handler, so
//! a softer signal would terminate it the same way; RocksDB stays consistent
//! across an abrupt exit via its write-ahead log.

/// Entry point for the `stop` subcommand. Kills all other sn-proxy processes,
/// cleans the pidfile under `data_dir`, prints a summary, and exits the process
/// (0 when nothing failed, 1 when at least one process could not be terminated).
pub fn run(data_dir: &str) -> ! {
    let target = target_image_name();
    let self_pid = std::process::id();

    let mut pids = enumerate_pids(&target);
    pids.retain(|&pid| pid != self_pid && pid != 0);
    pids.sort_unstable();
    pids.dedup();

    if pids.is_empty() {
        println!("no other {target} process is running");
        cleanup_pidfile(data_dir);
        std::process::exit(0);
    }

    let mut killed = Vec::new();
    let mut failed = Vec::new();
    for pid in pids {
        match terminate(pid) {
            Ok(()) => killed.push(pid),
            Err(e) => failed.push((pid, e)),
        }
    }

    if !killed.is_empty() {
        let list = killed
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        println!("stopped {} {target} process(es): {list}", killed.len());
    }
    for (pid, err) in &failed {
        eprintln!("warning: could not stop pid {pid}: {err}");
    }

    cleanup_pidfile(data_dir);
    std::process::exit(if failed.is_empty() { 0 } else { 1 });
}

/// Executable basename to match processes against (`sn-proxy.exe` / `sn-proxy`),
/// taken from the running binary so a renamed build still finds its own kin.
fn target_image_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| {
            if cfg!(windows) {
                "sn-proxy.exe".to_string()
            } else {
                "sn-proxy".to_string()
            }
        })
}

/// Case-insensitive comparison of a process image basename against the target.
/// Windows paths are case-insensitive; on Unix exact-case is the norm but
/// folding case here is harmless and forgiving of odd argv[0] casing.
fn name_matches(candidate: &str, target: &str) -> bool {
    candidate.eq_ignore_ascii_case(target)
}

/// Remove the daemon pidfile (best-effort). A missing file is the common case
/// after killing by image name and is not reported.
fn cleanup_pidfile(data_dir: &str) {
    let pidfile = std::path::Path::new(data_dir).join("sn-proxy.pid");
    match std::fs::remove_file(&pidfile) {
        Ok(()) => println!("removed pidfile {}", pidfile.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => eprintln!(
            "warning: could not remove pidfile {}: {e}",
            pidfile.display()
        ),
    }
}

#[cfg(target_os = "windows")]
fn enumerate_pids(target: &str) -> Vec<u32> {
    use windows_sys::Win32::System::ProcessStatus::EnumProcesses;

    // EnumProcesses cannot report that it truncated other than by filling the
    // buffer, so grow and retry until the written byte count is strictly below
    // the buffer size.
    let mut cap = 1024usize;
    loop {
        let mut buf = vec![0u32; cap];
        let cb = (buf.len() * std::mem::size_of::<u32>()) as u32;
        let mut needed = 0u32;
        // SAFETY: buf holds `cap` u32s; `cb` is its exact byte length; `needed`
        // receives the bytes written. All pointers are valid for the call.
        let ok = unsafe { EnumProcesses(buf.as_mut_ptr(), cb, &mut needed) };
        if ok == 0 {
            return Vec::new();
        }
        if needed >= cb {
            cap *= 2;
            continue;
        }
        let count = needed as usize / std::mem::size_of::<u32>();
        buf.truncate(count);
        return buf
            .into_iter()
            .filter(|&pid| pid != 0 && image_matches(pid, target))
            .collect();
    }
}

#[cfg(target_os = "windows")]
fn image_matches(pid: u32, target: &str) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };

    // SAFETY: the handle is checked for null and always closed; the call writes
    // up to `size` u16s into `buf` and updates `size` to the chars written.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            // System / other-user / already-exited processes: not ours to match.
            return false;
        }
        let mut buf = [0u16; 1024];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut size);
        CloseHandle(h);
        if ok == 0 {
            return false;
        }
        let path = String::from_utf16_lossy(&buf[..size as usize]);
        std::path::Path::new(&path)
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| name_matches(n, target))
    }
}

#[cfg(target_os = "windows")]
fn terminate(pid: u32) -> Result<(), String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

    // SAFETY: the handle is checked for null and always closed; TerminateProcess
    // takes it by value and the exit code is an arbitrary non-zero marker.
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if h.is_null() {
            return Err("could not open process (access denied or already exited)".to_string());
        }
        let ok = TerminateProcess(h, 1);
        CloseHandle(h);
        if ok == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }
}

#[cfg(unix)]
fn enumerate_pids(target: &str) -> Vec<u32> {
    let mut pids = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return pids;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if image_matches(pid, target) {
            pids.push(pid);
        }
    }
    pids
}

#[cfg(unix)]
fn image_matches(pid: u32, target: &str) -> bool {
    // Prefer the exe symlink basename — full and untruncated — and fall back to
    // /proc/<pid>/comm (truncated to 15 chars) when the link is unreadable.
    if let Ok(path) = std::fs::read_link(format!("/proc/{pid}/exe")) {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            return name_matches(name, target);
        }
    }
    if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
        return name_matches(comm.trim(), target);
    }
    false
}

#[cfg(unix)]
fn terminate(pid: u32) -> Result<(), String> {
    // SAFETY: kill is a plain syscall wrapper; the kernel validates pid and sig.
    let rc = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::name_matches;

    #[test]
    fn name_matches_is_case_insensitive() {
        assert!(name_matches("sn-proxy.exe", "sn-proxy.exe"));
        assert!(name_matches("SN-Proxy.EXE", "sn-proxy.exe"));
        assert!(name_matches("sn-proxy", "sn-proxy"));
    }

    #[test]
    fn name_matches_rejects_other_binaries() {
        assert!(!name_matches("not-sn-proxy.exe", "sn-proxy.exe"));
        assert!(!name_matches("sn-proxy-helper", "sn-proxy"));
        assert!(!name_matches("", "sn-proxy"));
    }
}
