//! Windows process + connection collection via Win32 (user-mode, no admin).
//!
//! These are the same primitives an EDR / anti-cheat engine reaches for, and
//! the same small FFI surface used by the sibling `sentinel` crate. Copied
//! here on purpose so `pulse` has zero dependency on `sentinel`.

use crate::snapshot::{Connection, ProcessInfo};
use std::net::Ipv4Addr;

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::ProcessStatus::K32GetModuleBaseNameA;
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;

/// Enumerate the host process tree via the Toolhelp snapshot API.
pub(super) fn processes() -> Vec<ProcessInfo> {
    let mut out = Vec::new();
    unsafe {
        // CreateToolhelp32Snapshot returns INVALID_HANDLE_VALUE (-1) on failure.
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snap, &mut entry) != 0 {
            loop {
                let pid = entry.th32ProcessID;
                let ppid = entry.th32ParentProcessID;
                let name = process_name(pid);
                out.push(ProcessInfo {
                    pid,
                    parent_pid: ppid,
                    name,
                });
                if Process32Next(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    out
}

/// Resolve a process image name. `GetModuleBaseNameA` accepts a NULL module
/// handle to mean "the first module" (the executable image itself), so we call
/// it directly rather than first enumerating modules — that avoids the
/// too-small-buffer short-circuit the reference `sentinel` FFI hits. Falls back
/// to a `<pid N>` placeholder when the call is denied (protected process) so a
/// single inaccessible process never aborts the whole sweep.
fn process_name(pid: u32) -> String {
    unsafe {
        // OpenProcess returns NULL (0) on failure, not INVALID_HANDLE_VALUE.
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if handle == 0 {
            return format!("<pid {}>", pid);
        }
        let mut buf = [0u8; 260];
        let n = K32GetModuleBaseNameA(handle, 0isize, buf.as_mut_ptr(), buf.len() as u32);
        CloseHandle(handle);
        if n == 0 {
            return format!("<pid {}>", pid);
        }
        let end = (n as usize).min(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    }
}

/// Enumerate IPv4 TCP sockets with owning PIDs via `GetExtendedTcpTable`.
pub(super) fn connections() -> Vec<Connection> {
    let mut out = Vec::new();
    unsafe {
        // First call sizes the buffer.
        let mut size: u32 = 0;
        let _ = GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if size == 0 {
            return out;
        }
        let mut buf: Vec<u8> = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if ret != 0 {
            return out;
        }
        let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
        let count = (*table).dwNumEntries;
        let base = &(*table).table[0] as *const MIB_TCPROW_OWNER_PID;
        for i in 0..count {
            let row = &*base.add(i as usize);
            out.push(Connection {
                pid: row.dwOwningPid,
                local_addr: sock(row.dwLocalAddr, row.dwLocalPort),
                remote_addr: sock(row.dwRemoteAddr, row.dwRemotePort),
                state: tcp_state(row.dwState),
            });
        }
    }
    out
}

/// Format an IPv4 address + port. Address / port arrive in network byte order.
fn sock(addr_be: u32, port_be: u32) -> String {
    let ip = Ipv4Addr::from(u32::from_be(addr_be));
    let port = u16::from_be(port_be as u16);
    format!("{}:{}", ip, port)
}

/// Map `MIB_TCP_STATE_*` values to names.
fn tcp_state(s: u32) -> String {
    match s {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => return format!("STATE_{}", s),
    }
    .to_string()
}
