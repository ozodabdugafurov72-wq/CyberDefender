//! CyberDefender Rust Process Sensor v0.5.1
//!
//! Security scope:
//! - Windows x64 process observation only;
//! - no remediation, injection, remote memory writes, registry writes or network I/O;
//! - bounded process enumeration and bounded IPC frames;
//! - persistent framed local IPC mode for supervised canary use;
//! - enrichment is best-effort and carries explicit per-field status;
//! - process identity remains PID + exact Windows creation FILETIME.
#![deny(unsafe_op_in_unsafe_fn)]

use std::io::{self, Read, Write};

const MAX_PROCESSES: usize = 5000;
const MAX_OUTPUT: usize = 12 * 1024 * 1024;
const EPOCH_TICKS: u64 = 116_444_736_000_000_000;
const IPC_MAGIC: [u8; 4] = *b"CDRQ";
const IPC_VERSION: u16 = 1;
const IPC_OP_HELLO: u16 = 1;
const IPC_OP_SNAPSHOT: u16 = 2;
const IPC_OP_SHUTDOWN: u16 = 3;
const IPC_REQUEST_SIZE: usize = 16;

#[derive(Debug, Clone)]
struct FieldStatus {
    status: &'static str,
}

impl FieldStatus {
    fn collected() -> Self { Self { status: "COLLECTED" } }
    fn access_denied() -> Self { Self { status: "ACCESS_DENIED" } }
    fn query_failed() -> Self { Self { status: "QUERY_FAILED" } }
    fn unavailable() -> Self { Self { status: "UNAVAILABLE" } }
    fn not_collected() -> Self { Self { status: "NOT_COLLECTED_V05_CORE" } }
}

#[derive(Debug)]
struct Process {
    pid: u32,
    ppid: u32,
    name: String,
    created: u64,
    exe: Option<String>,
    exe_status: FieldStatus,
    username: Option<String>,
    username_status: FieldStatus,
    sid: Option<String>,
    sid_status: FieldStatus,
    cmdline: Option<Vec<String>>,
    cmdline_status: FieldStatus,
    session_id: Option<u32>,
    session_status: FieldStatus,
    integrity_level: Option<String>,
    integrity_status: FieldStatus,
}

#[derive(Debug)]
struct Skipped {
    pid: u32,
    reason: &'static str,
    win32_error: Option<u32>,
}

#[derive(Debug, Clone)]
struct IpcMeta {
    sequence: u64,
    sensor_epoch: String,
    supervisor_pid: u32,
    sensor_pid: u32,
}

#[derive(Debug)]
struct IpcRequest {
    version: u16,
    op: u16,
    sequence: u64,
}

fn open_failure(pid: u32, code: u32) -> Skipped {
    let reason = if pid == 0 && code == 87 {
        "SYSTEM_IDLE_UNQUERYABLE"
    } else if code == 5 {
        "OPEN_ACCESS_DENIED"
    } else {
        "OPEN_FAILED"
    };
    Skipped { pid, reason, win32_error: Some(code) }
}

fn unix_seconds(ticks: u64) -> Result<f64, &'static str> {
    if ticks < EPOCH_TICKS { return Err("invalid creation epoch"); }
    Ok((ticks - EPOCH_TICKS) as f64 / 10_000_000.0)
}

fn quoted(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c <= '\u{1f}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn encode_optional_string(value: &Option<String>) -> String {
    match value {
        Some(v) => quoted(v),
        None => "null".into(),
    }
}

fn encode_optional_u32(value: Option<u32>) -> String {
    match value {
        Some(v) => v.to_string(),
        None => "null".into(),
    }
}

fn encode_optional_args(value: &Option<Vec<String>>) -> String {
    match value {
        None => "null".into(),
        Some(args) => {
            let mut out = String::from("[");
            for (i, arg) in args.iter().enumerate() {
                if i != 0 { out.push(','); }
                out.push_str(&quoted(arg));
            }
            out.push(']');
            out
        }
    }
}

fn encode_status(status: &FieldStatus) -> String {
    format!("{{\"status\":{}}}", quoted(status.status))
}

fn enrichment_provenance_json() -> &'static str {
    concat!(
        "{",
        "\"exe\":{\"source\":\"QueryFullProcessImageNameW\",\"confidence\":\"HIGH\"},",
        "\"cmdline\":{\"source\":\"NtQueryInformationProcess+CommandLineToArgvW\",\"confidence\":\"HIGH_WHEN_COLLECTED\"},",
        "\"username\":{\"source\":\"OpenProcessToken+LookupAccountSidW\",\"confidence\":\"HIGH_WHEN_COLLECTED\"},",
        "\"sid\":{\"source\":\"OpenProcessToken+ConvertSidToStringSidW\",\"confidence\":\"HIGH_WHEN_COLLECTED\"},",
        "\"session_id\":{\"source\":\"ProcessIdToSessionId\",\"confidence\":\"HIGH_WHEN_COLLECTED\"},",
        "\"integrity_level\":{\"source\":\"TokenIntegrityLevel\",\"confidence\":\"HIGH_WHEN_COLLECTED\"},",
        "\"cpu_percent\":{\"source\":\"DEFERRED_TO_PERSISTENT_METRICS_TIER\",\"confidence\":\"NOT_AVAILABLE_V05_CORE\"},",
        "\"memory_percent\":{\"source\":\"DEFERRED_TO_PERSISTENT_METRICS_TIER\",\"confidence\":\"NOT_AVAILABLE_V05_CORE\"}",
        "}"
    )
}

fn encode(
    rows: &[Process],
    skipped: &[Skipped],
    started: u64,
    ipc: Option<&IpcMeta>,
) -> Result<String, &'static str> {
    if rows.len() + skipped.len() > MAX_PROCESSES {
        return Err("process limit exceeded");
    }

    let mut seen = std::collections::HashSet::new();
    for pid in rows.iter().map(|p| p.pid).chain(skipped.iter().map(|p| p.pid)) {
        if !seen.insert(pid) { return Err("duplicate PID across observations"); }
    }

    let ipc_json = match ipc {
        None => "null".into(),
        Some(meta) => format!(
            "{{\"protocol\":\"cd.sensor.ipc.v1\",\"version\":1,\"sequence\":{},\"sensor_epoch\":{},\"supervisor_pid\":{},\"sensor_pid\":{}}}",
            meta.sequence,
            quoted(&meta.sensor_epoch),
            meta.supervisor_pid,
            meta.sensor_pid,
        ),
    };

    let mut out = format!(
        "{{\"schema\":\"cd.process.v5\",\"sensor\":\"RustProcessSensor\",\"version\":\"0.5.1\",\"timestamp\":{:.7},\"partial\":{},\"skipped\":{},\"process_count\":{},\"ipc\":{},\"enrichment_provenance\":{},\"processes\":[",
        unix_seconds(started)?,
        !skipped.is_empty(),
        skipped.len(),
        rows.len(),
        ipc_json,
        enrichment_provenance_json(),
    );

    for (i, p) in rows.iter().enumerate() {
        if p.name.encode_utf16().count() > 260 || p.name.is_empty() {
            return Err("invalid name");
        }
        if p.created > started { return Err("creation after snapshot start"); }
        if i != 0 { out.push(','); }

        let status_json = format!(
            "{{\"exe\":{},\"username\":{},\"sid\":{},\"cmdline\":{},\"session_id\":{},\"integrity_level\":{},\"cpu_percent\":{},\"memory_percent\":{}}}",
            encode_status(&p.exe_status),
            encode_status(&p.username_status),
            encode_status(&p.sid_status),
            encode_status(&p.cmdline_status),
            encode_status(&p.session_status),
            encode_status(&p.integrity_status),
            encode_status(&FieldStatus::not_collected()),
            encode_status(&FieldStatus::not_collected()),
        );

        out.push_str(&format!(
            "{{\"pid\":{},\"ppid\":{},\"name\":{},\"create_time\":{:.7},\"creation_filetime\":\"{}\",\"exe\":{},\"username\":{},\"cmdline\":{},\"sid\":{},\"session_id\":{},\"integrity_level\":{},\"cpu_percent\":null,\"memory_percent\":null,\"enrichment_status\":{}}}",
            p.pid,
            p.ppid,
            quoted(&p.name),
            unix_seconds(p.created)?,
            p.created,
            encode_optional_string(&p.exe),
            encode_optional_string(&p.username),
            encode_optional_args(&p.cmdline),
            encode_optional_string(&p.sid),
            encode_optional_u32(p.session_id),
            encode_optional_string(&p.integrity_level),
            status_json,
        ));

        if out.len() > MAX_OUTPUT - 4096 { return Err("output limit exceeded"); }
    }

    out.push_str("],\"skipped_processes\":[");
    for (i, item) in skipped.iter().enumerate() {
        if i != 0 { out.push(','); }
        let code = item.win32_error.map(|x| x.to_string()).unwrap_or_else(|| "null".into());
        out.push_str(&format!(
            "{{\"pid\":{},\"reason\":{},\"win32_error\":{}}}",
            item.pid,
            quoted(item.reason),
            code,
        ));
        if out.len() > MAX_OUTPUT - 1024 { return Err("output limit exceeded"); }
    }
    out.push_str("]}\n");

    if out.len() > MAX_OUTPUT { return Err("output limit exceeded"); }
    Ok(out)
}

fn parse_ipc_request(raw: &[u8]) -> Result<IpcRequest, &'static str> {
    if raw.len() != IPC_REQUEST_SIZE { return Err("invalid IPC request size"); }
    if raw[0..4] != IPC_MAGIC { return Err("invalid IPC magic"); }
    let version = u16::from_le_bytes([raw[4], raw[5]]);
    let op = u16::from_le_bytes([raw[6], raw[7]]);
    let sequence = u64::from_le_bytes([
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
    ]);
    if version != IPC_VERSION { return Err("unsupported IPC version"); }
    if !matches!(op, IPC_OP_HELLO | IPC_OP_SNAPSHOT | IPC_OP_SHUTDOWN) {
        return Err("unsupported IPC operation");
    }
    if sequence == 0 { return Err("invalid IPC sequence"); }
    Ok(IpcRequest { version, op, sequence })
}

fn write_frame(stdout: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    if payload.is_empty() || payload.len() > MAX_OUTPUT {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid frame length"));
    }
    let len = payload.len() as u32;
    stdout.write_all(&len.to_le_bytes())?;
    stdout.write_all(payload)?;
    stdout.flush()
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{
        collections::HashSet,
        ffi::c_void,
        mem::size_of,
        ptr,
        slice,
        time::{Duration, Instant},
    };

    type Handle = *mut c_void;
    type Bool = i32;
    type Dword = u32;
    type Ulong = u32;
    type NtStatus = i32;

    const INVALID_HANDLE: Handle = -1isize as Handle;
    const QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const SNAP_PROCESS: u32 = 2;
    const NO_MORE_FILES: u32 = 18;
    const ERROR_ACCESS_DENIED: u32 = 5;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER_CLASS: u32 = 1;
    const TOKEN_INTEGRITY_LEVEL_CLASS: u32 = 25;
    const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;
    const MAX_WIDE_PATH: usize = 32768;
    const MAX_COMMAND_LINE_BYTES: usize = 128 * 1024;

    #[repr(C)]
    struct Entry {
        size: u32,
        usage: u32,
        pid: u32,
        heap: usize,
        module: u32,
        threads: u32,
        ppid: u32,
        priority: i32,
        flags: u32,
        name: [u16; 260],
    }

    #[repr(C)]
    #[derive(Default)]
    struct FileTime { low: u32, high: u32 }

    impl FileTime {
        fn ticks(&self) -> u64 { ((self.high as u64) << 32) | self.low as u64 }
    }

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    #[repr(C)]
    struct SidAndAttributes {
        sid: *mut c_void,
        attributes: u32,
    }

    #[repr(C)]
    struct TokenUser {
        user: SidAndAttributes,
    }

    #[repr(C)]
    struct TokenMandatoryLabel {
        label: SidAndAttributes,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateToolhelp32Snapshot(flags: Dword, pid: Dword) -> Handle;
        fn Process32FirstW(snapshot: Handle, entry: *mut Entry) -> Bool;
        fn Process32NextW(snapshot: Handle, entry: *mut Entry) -> Bool;
        fn OpenProcess(access: Dword, inherit: Bool, pid: Dword) -> Handle;
        fn GetProcessTimes(
            process: Handle,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> Bool;
        fn GetSystemTimeAsFileTime(time: *mut FileTime);
        fn CloseHandle(handle: Handle) -> Bool;
        fn GetLastError() -> Dword;
        fn QueryFullProcessImageNameW(
            process: Handle,
            flags: Dword,
            buffer: *mut u16,
            size: *mut Dword,
        ) -> Bool;
        fn ProcessIdToSessionId(pid: Dword, session_id: *mut Dword) -> Bool;
        fn LocalFree(memory: Handle) -> Handle;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(process: Handle, desired_access: Dword, token: *mut Handle) -> Bool;
        fn GetTokenInformation(
            token: Handle,
            token_information_class: Dword,
            token_information: *mut c_void,
            token_information_length: Dword,
            return_length: *mut Dword,
        ) -> Bool;
        fn ConvertSidToStringSidW(sid: *mut c_void, string_sid: *mut *mut u16) -> Bool;
        fn LookupAccountSidW(
            system_name: *const u16,
            sid: *mut c_void,
            name: *mut u16,
            name_len: *mut Dword,
            domain: *mut u16,
            domain_len: *mut Dword,
            sid_name_use: *mut Dword,
        ) -> Bool;
        fn GetSidSubAuthorityCount(sid: *mut c_void) -> *mut u8;
        fn GetSidSubAuthority(sid: *mut c_void, index: Dword) -> *mut Dword;
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryInformationProcess(
            process: Handle,
            process_information_class: Ulong,
            process_information: *mut c_void,
            process_information_length: Ulong,
            return_length: *mut Ulong,
        ) -> NtStatus;
    }

    #[link(name = "shell32")]
    extern "system" {
        fn CommandLineToArgvW(command_line: *const u16, argc: *mut i32) -> *mut *mut u16;
    }

    struct OwnedHandle(Handle);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0); }
        }
    }

    fn status_from_win32(code: u32) -> FieldStatus {
        if code == ERROR_ACCESS_DENIED {
            FieldStatus::access_denied()
        } else {
            FieldStatus::query_failed()
        }
    }

    unsafe fn wide_ptr_to_string(ptr_w: *const u16, max_chars: usize) -> Option<String> {
        if ptr_w.is_null() { return None; }
        let mut len = 0usize;
        while len < max_chars {
            let value = unsafe { *ptr_w.add(len) };
            if value == 0 { break; }
            len += 1;
        }
        if len == max_chars { return None; }
        let units = unsafe { slice::from_raw_parts(ptr_w, len) };
        String::from_utf16(units).ok()
    }

    fn query_exe(process: Handle) -> (Option<String>, FieldStatus) {
        let mut buffer = vec![0u16; MAX_WIDE_PATH];
        let mut size = buffer.len() as Dword;
        let ok = unsafe {
            QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut size)
        };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return (None, status_from_win32(code));
        }
        let used = size as usize;
        if used == 0 || used > buffer.len() {
            return (None, FieldStatus::query_failed());
        }
        match String::from_utf16(&buffer[..used]) {
            Ok(text) if !text.is_empty() => (Some(text), FieldStatus::collected()),
            _ => (None, FieldStatus::query_failed()),
        }
    }

    fn query_cmdline(process: Handle) -> (Option<Vec<String>>, FieldStatus) {
        let mut buffer = vec![0u8; MAX_COMMAND_LINE_BYTES];
        let mut returned: Ulong = 0;
        let status = unsafe {
            NtQueryInformationProcess(
                process,
                PROCESS_COMMAND_LINE_INFORMATION,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as Ulong,
                &mut returned,
            )
        };
        if status < 0 {
            return (None, FieldStatus::query_failed());
        }
        if buffer.len() < size_of::<UnicodeString>() {
            return (None, FieldStatus::query_failed());
        }

        let us = unsafe { ptr::read_unaligned(buffer.as_ptr() as *const UnicodeString) };
        let byte_len = us.length as usize;
        if byte_len == 0 {
            return (Some(Vec::new()), FieldStatus::collected());
        }
        if byte_len % 2 != 0 || byte_len > MAX_COMMAND_LINE_BYTES - 2 || us.buffer.is_null() {
            return (None, FieldStatus::query_failed());
        }

        let base = buffer.as_ptr() as usize;
        let end = base.saturating_add(buffer.len());
        let ptr_value = us.buffer as usize;
        let ptr_end = ptr_value.saturating_add(byte_len);
        if ptr_value < base || ptr_end > end {
            return (None, FieldStatus::query_failed());
        }

        let units = unsafe { slice::from_raw_parts(us.buffer, byte_len / 2) };
        let mut nul = Vec::with_capacity(units.len() + 1);
        nul.extend_from_slice(units);
        nul.push(0);

        let mut argc: i32 = 0;
        let argv = unsafe { CommandLineToArgvW(nul.as_ptr(), &mut argc) };
        if argv.is_null() || argc < 0 || argc > 4096 {
            return (None, FieldStatus::query_failed());
        }

        let mut args = Vec::with_capacity(argc as usize);
        let mut valid = true;
        for index in 0..argc as usize {
            let arg_ptr = unsafe { *argv.add(index) };
            match unsafe { wide_ptr_to_string(arg_ptr, MAX_WIDE_PATH) } {
                Some(value) => args.push(value),
                None => {
                    valid = false;
                    break;
                }
            }
        }
        unsafe { LocalFree(argv as Handle); }

        if valid {
            (Some(args), FieldStatus::collected())
        } else {
            (None, FieldStatus::query_failed())
        }
    }

    fn token_buffer(token: Handle, class_id: u32) -> Result<Vec<u8>, FieldStatus> {
        let mut required: Dword = 0;
        unsafe {
            GetTokenInformation(
                token,
                class_id,
                ptr::null_mut(),
                0,
                &mut required,
            );
        }
        if required == 0 || required > 1024 * 1024 {
            return Err(FieldStatus::query_failed());
        }
        let mut buffer = vec![0u8; required as usize];
        let ok = unsafe {
            GetTokenInformation(
                token,
                class_id,
                buffer.as_mut_ptr() as *mut c_void,
                required,
                &mut required,
            )
        };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(status_from_win32(code));
        }
        Ok(buffer)
    }

    fn sid_to_string(sid: *mut c_void) -> (Option<String>, FieldStatus) {
        if sid.is_null() { return (None, FieldStatus::query_failed()); }
        let mut ptr_w: *mut u16 = ptr::null_mut();
        let ok = unsafe { ConvertSidToStringSidW(sid, &mut ptr_w) };
        if ok == 0 || ptr_w.is_null() {
            let code = unsafe { GetLastError() };
            return (None, status_from_win32(code));
        }
        let value = unsafe { wide_ptr_to_string(ptr_w, 512) };
        unsafe { LocalFree(ptr_w as Handle); }
        match value {
            Some(text) if !text.is_empty() => (Some(text), FieldStatus::collected()),
            _ => (None, FieldStatus::query_failed()),
        }
    }

    fn sid_to_username(sid: *mut c_void) -> (Option<String>, FieldStatus) {
        if sid.is_null() { return (None, FieldStatus::query_failed()); }
        let mut name_len: Dword = 0;
        let mut domain_len: Dword = 0;
        let mut sid_type: Dword = 0;
        unsafe {
            LookupAccountSidW(
                ptr::null(),
                sid,
                ptr::null_mut(),
                &mut name_len,
                ptr::null_mut(),
                &mut domain_len,
                &mut sid_type,
            );
        }
        if name_len == 0 || name_len > 32768 || domain_len > 32768 {
            return (None, FieldStatus::unavailable());
        }
        let mut name = vec![0u16; name_len as usize];
        let mut domain = vec![0u16; domain_len.max(1) as usize];
        let ok = unsafe {
            LookupAccountSidW(
                ptr::null(),
                sid,
                name.as_mut_ptr(),
                &mut name_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut sid_type,
            )
        };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return (None, status_from_win32(code));
        }
        let name_used = name.iter().position(|x| *x == 0).unwrap_or(name.len());
        let domain_used = domain.iter().position(|x| *x == 0).unwrap_or(domain.len());
        let name_text = String::from_utf16(&name[..name_used]).ok();
        let domain_text = if domain_used > 0 {
            String::from_utf16(&domain[..domain_used]).ok()
        } else {
            Some(String::new())
        };
        match (domain_text, name_text) {
            (Some(domain), Some(user)) if !user.is_empty() => {
                let value = if domain.is_empty() { user } else { format!("{}\\{}", domain, user) };
                (Some(value), FieldStatus::collected())
            }
            _ => (None, FieldStatus::query_failed()),
        }
    }

    fn integrity_from_sid(sid: *mut c_void) -> (Option<String>, FieldStatus) {
        if sid.is_null() { return (None, FieldStatus::query_failed()); }
        let count_ptr = unsafe { GetSidSubAuthorityCount(sid) };
        if count_ptr.is_null() { return (None, FieldStatus::query_failed()); }
        let count = unsafe { *count_ptr };
        if count == 0 { return (None, FieldStatus::query_failed()); }
        let rid_ptr = unsafe { GetSidSubAuthority(sid, (count - 1) as u32) };
        if rid_ptr.is_null() { return (None, FieldStatus::query_failed()); }
        let rid = unsafe { *rid_ptr };
        let level = match rid {
            0x0000..=0x0fff => "UNTRUSTED",
            0x1000..=0x1fff => "LOW",
            0x2000..=0x20ff => "MEDIUM",
            0x2100..=0x2fff => "MEDIUM_PLUS",
            0x3000..=0x3fff => "HIGH",
            0x4000..=0x4fff => "SYSTEM",
            0x5000..=0x5fff => "PROTECTED",
            _ => "UNKNOWN",
        };
        (Some(level.into()), FieldStatus::collected())
    }

    struct TokenResult {
        username: Option<String>,
        username_status: FieldStatus,
        sid: Option<String>,
        sid_status: FieldStatus,
        integrity_level: Option<String>,
        integrity_status: FieldStatus,
    }

    fn query_token(process: Handle) -> TokenResult {
        let mut raw_token: Handle = ptr::null_mut();
        let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw_token) };
        if opened == 0 || raw_token.is_null() {
            let code = unsafe { GetLastError() };
            let status = status_from_win32(code);
            return TokenResult {
                username: None,
                username_status: status.clone(),
                sid: None,
                sid_status: status.clone(),
                integrity_level: None,
                integrity_status: status,
            };
        }
        let token = OwnedHandle(raw_token);

        let (username, username_status, sid_value, sid_status) = match token_buffer(token.0, TOKEN_USER_CLASS) {
            Ok(buffer) if buffer.len() >= size_of::<TokenUser>() => {
                let token_user = unsafe { ptr::read_unaligned(buffer.as_ptr() as *const TokenUser) };
                let sid_ptr = token_user.user.sid;
                let (sid_text, sid_st) = sid_to_string(sid_ptr);
                let (user_text, user_st) = sid_to_username(sid_ptr);
                (user_text, user_st, sid_text, sid_st)
            }
            Ok(_) => (None, FieldStatus::query_failed(), None, FieldStatus::query_failed()),
            Err(status) => (None, status.clone(), None, status),
        };

        let (integrity_level, integrity_status) = match token_buffer(token.0, TOKEN_INTEGRITY_LEVEL_CLASS) {
            Ok(buffer) if buffer.len() >= size_of::<TokenMandatoryLabel>() => {
                let label = unsafe { ptr::read_unaligned(buffer.as_ptr() as *const TokenMandatoryLabel) };
                integrity_from_sid(label.label.sid)
            }
            Ok(_) => (None, FieldStatus::query_failed()),
            Err(status) => (None, status),
        };

        TokenResult {
            username,
            username_status,
            sid: sid_value,
            sid_status,
            integrity_level,
            integrity_status,
        }
    }

    fn query_session(pid: u32) -> (Option<u32>, FieldStatus) {
        let mut session_id: Dword = 0;
        let ok = unsafe { ProcessIdToSessionId(pid, &mut session_id) };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return (None, status_from_win32(code));
        }
        (Some(session_id), FieldStatus::collected())
    }

    pub fn system_filetime() -> u64 {
        let mut now = FileTime::default();
        unsafe { GetSystemTimeAsFileTime(&mut now); }
        now.ticks()
    }

    pub fn collect(ipc: Option<&IpcMeta>) -> Result<String, String> {
        if size_of::<usize>() != 8 || size_of::<Entry>() != 568 {
            return Err("unsupported ABI: Windows x64 required".into());
        }
        let deadline = Instant::now() + Duration::from_secs(4);
        let started_ticks = system_filetime();

        let raw = unsafe { CreateToolhelp32Snapshot(SNAP_PROCESS, 0) };
        if raw == INVALID_HANDLE || raw.is_null() {
            return Err(format!("snapshot failed: {}", unsafe { GetLastError() }));
        }
        let snapshot = OwnedHandle(raw);

        let mut entry = Entry {
            size: size_of::<Entry>() as u32,
            usage: 0,
            pid: 0,
            heap: 0,
            module: 0,
            threads: 0,
            ppid: 0,
            priority: 0,
            flags: 0,
            name: [0; 260],
        };

        let mut rows = Vec::new();
        let mut seen = HashSet::new();
        let mut skipped = Vec::new();

        let mut ok = unsafe { Process32FirstW(snapshot.0, &mut entry) };
        loop {
            if ok == 0 {
                let code = unsafe { GetLastError() };
                if code != NO_MORE_FILES {
                    return Err(format!("enumeration failed: {code}"));
                }
                break;
            }
            if Instant::now() >= deadline {
                return Err("collection deadline exceeded".into());
            }
            if seen.len() >= MAX_PROCESSES {
                return Err("process limit exceeded".into());
            }
            if !seen.insert(entry.pid) {
                return Err("duplicate PID in snapshot".into());
            }

            let name_len = entry.name.iter().position(|x| *x == 0).unwrap_or(260);
            let name = String::from_utf16(&entry.name[..name_len]);

            let process = unsafe { OpenProcess(QUERY_LIMITED_INFORMATION, 0, entry.pid) };
            if process.is_null() {
                let code = unsafe { GetLastError() };
                skipped.push(open_failure(entry.pid, code));
            } else {
                let process = OwnedHandle(process);
                let (mut c, mut e, mut k, mut u) = (
                    FileTime::default(),
                    FileTime::default(),
                    FileTime::default(),
                    FileTime::default(),
                );
                let got = unsafe {
                    GetProcessTimes(process.0, &mut c, &mut e, &mut k, &mut u)
                };
                if got == 0 {
                    let code = unsafe { GetLastError() };
                    skipped.push(Skipped {
                        pid: entry.pid,
                        reason: "TIMES_FAILED",
                        win32_error: Some(code),
                    });
                } else if c.ticks() < EPOCH_TICKS {
                    skipped.push(Skipped {
                        pid: entry.pid,
                        reason: "INVALID_CREATION_TIME",
                        win32_error: None,
                    });
                } else if c.ticks() > started_ticks {
                    skipped.push(Skipped {
                        pid: entry.pid,
                        reason: "CREATED_AFTER_SNAPSHOT_START",
                        win32_error: None,
                    });
                } else {
                    match name {
                        Ok(name) if !name.is_empty() => {
                            let (exe, exe_status) = query_exe(process.0);
                            let (cmdline, cmdline_status) = query_cmdline(process.0);
                            let token = query_token(process.0);
                            let (session_id, session_status) = query_session(entry.pid);

                            rows.push(Process {
                                pid: entry.pid,
                                ppid: entry.ppid,
                                name,
                                created: c.ticks(),
                                exe,
                                exe_status,
                                username: token.username,
                                username_status: token.username_status,
                                sid: token.sid,
                                sid_status: token.sid_status,
                                cmdline,
                                cmdline_status,
                                session_id,
                                session_status,
                                integrity_level: token.integrity_level,
                                integrity_status: token.integrity_status,
                            });
                        }
                        _ => skipped.push(Skipped {
                            pid: entry.pid,
                            reason: "INVALID_NAME",
                            win32_error: None,
                        }),
                    }
                }
            }

            ok = unsafe { Process32NextW(snapshot.0, &mut entry) };
        }

        if seen.is_empty() { return Err("empty process enumeration".into()); }
        rows.sort_by_key(|p| p.pid);
        skipped.sort_by_key(|p| p.pid);
        encode(&rows, &skipped, started_ticks, ipc).map_err(str::to_owned)
    }

    #[test]
    fn abi_layout_x64() {
        assert_eq!(size_of::<Entry>(), 568);
        assert_eq!(size_of::<FileTime>(), 8);
        assert_eq!(size_of::<UnicodeString>(), 16);
    }

    #[test]
    fn live_snapshot_has_self() {
        let data = collect(None).expect("live Windows collection");
        let observations = data.split("\"skipped_processes\"").next().unwrap();
        assert!(observations.contains(&format!("\"pid\":{},", std::process::id())));
        assert!(data.contains("\"schema\":\"cd.process.v5\""));
        assert!(data.contains("\"enrichment_status\""));
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    pub fn system_filetime() -> u64 { EPOCH_TICKS }
    pub fn collect(_ipc: Option<&IpcMeta>) -> Result<String, String> {
        Err("Windows x64 required".into())
    }
}

fn hello_payload(
    sequence: u64,
    epoch: &str,
    supervisor_pid: u32,
    launch_nonce: &str,
) -> String {
    format!(
        "{{\"schema\":\"cd.sensor.hello.v1\",\"protocol\":\"cd.sensor.ipc.v1\",\"version\":1,\"sequence\":{},\"sensor\":\"RustProcessSensor\",\"sensor_version\":\"0.5.1\",\"sensor_epoch\":{},\"sensor_pid\":{},\"supervisor_pid\":{},\"launch_nonce\":{}}}\n",
        sequence,
        quoted(epoch),
        std::process::id(),
        supervisor_pid,
        quoted(launch_nonce),
    )
}

fn goodbye_payload(sequence: u64, epoch: &str) -> String {
    format!(
        "{{\"schema\":\"cd.sensor.goodbye.v1\",\"protocol\":\"cd.sensor.ipc.v1\",\"version\":1,\"sequence\":{},\"sensor_epoch\":{}}}\n",
        sequence,
        quoted(epoch),
    )
}

fn run_ipc() -> Result<(), String> {
    let launch_nonce = std::env::var("CYBERDEFENDER_SENSOR_LAUNCH_NONCE")
        .map_err(|_| "missing launch nonce".to_string())?;
    if launch_nonce.len() != 64
        || !launch_nonce.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("invalid launch nonce".into());
    }
    let supervisor_pid: u32 = std::env::var("CYBERDEFENDER_SENSOR_SUPERVISOR_PID")
        .map_err(|_| "missing supervisor PID".to_string())?
        .parse()
        .map_err(|_| "invalid supervisor PID".to_string())?;
    if supervisor_pid == 0 {
        return Err("invalid supervisor PID".into());
    }

    let startup_ticks = platform::system_filetime();
    let epoch = format!("{}-{}", startup_ticks, std::process::id());
    let mut last_sequence = 0u64;
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();

    loop {
        let mut request_raw = [0u8; IPC_REQUEST_SIZE];
        stdin.read_exact(&mut request_raw).map_err(|e| format!("IPC read failed: {e}"))?;
        let request = parse_ipc_request(&request_raw).map_err(str::to_owned)?;
        if request.version != IPC_VERSION {
            return Err("IPC version mismatch".into());
        }
        if request.sequence <= last_sequence {
            return Err("IPC replay/out-of-order sequence".into());
        }
        last_sequence = request.sequence;

        match request.op {
            IPC_OP_HELLO => {
                let payload = hello_payload(request.sequence, &epoch, supervisor_pid, &launch_nonce);
                write_frame(&mut stdout, payload.as_bytes()).map_err(|e| e.to_string())?;
            }
            IPC_OP_SNAPSHOT => {
                let meta = IpcMeta {
                    sequence: request.sequence,
                    sensor_epoch: epoch.clone(),
                    supervisor_pid,
                    sensor_pid: std::process::id(),
                };
                let payload = platform::collect(Some(&meta))?;
                write_frame(&mut stdout, payload.as_bytes()).map_err(|e| e.to_string())?;
            }
            IPC_OP_SHUTDOWN => {
                let payload = goodbye_payload(request.sequence, &epoch);
                write_frame(&mut stdout, payload.as_bytes()).map_err(|e| e.to_string())?;
                return Ok(());
            }
            _ => return Err("unsupported IPC operation".into()),
        }
    }
}

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let result = if args.len() == 1 {
        platform::collect(None).and_then(|data| {
            io::stdout().lock().write_all(data.as_bytes()).map_err(|e| e.to_string())?;
            Ok(String::new())
        })
    } else if args.len() == 2 && args[1] == std::ffi::OsStr::new("--ipc") {
        run_ipc().map(|_| String::new())
    } else {
        Err("sensor accepts only optional --ipc".into())
    };

    if let Err(error) = result {
        eprintln!("sensor failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_process() -> Process {
        Process {
            pid: 10,
            ppid: 1,
            name: "test.exe".into(),
            created: EPOCH_TICKS + 1,
            exe: Some("C:\\test.exe".into()),
            exe_status: FieldStatus::collected(),
            username: Some("DOMAIN\\user".into()),
            username_status: FieldStatus::collected(),
            sid: Some("S-1-5-21-1".into()),
            sid_status: FieldStatus::collected(),
            cmdline: Some(vec!["C:\\test.exe".into(), "--x".into()]),
            cmdline_status: FieldStatus::collected(),
            session_id: Some(1),
            session_status: FieldStatus::collected(),
            integrity_level: Some("MEDIUM".into()),
            integrity_status: FieldStatus::collected(),
        }
    }

    #[test]
    fn epoch_conversion() {
        assert_eq!(unix_seconds(EPOCH_TICKS).unwrap(), 0.0);
        assert_eq!(unix_seconds(EPOCH_TICKS + 15_000_000).unwrap(), 1.5);
        assert!(unix_seconds(EPOCH_TICKS - 1).is_err());
    }

    #[test]
    fn integer_first_identity_compatibility() {
        let ticks = EPOCH_TICKS + 17_888_000_000_000_054;
        let selected = unix_seconds(ticks).unwrap();
        let integer_first = (ticks - EPOCH_TICKS) as f64 / 10_000_000.0;
        assert_eq!(selected, integer_first);
    }

    #[test]
    fn json_escaping() {
        assert_eq!(quoted("a\"\\\n\0"), "\"a\\\"\\\\\\n\\u0000\"");
    }

    #[test]
    fn v5_enrichment_schema_is_emitted() {
        let p = sample_process();
        let data = encode(&[p], &[], EPOCH_TICKS + 100, None).unwrap();
        assert!(data.contains("\"schema\":\"cd.process.v5\""));
        assert!(data.contains("\"version\":\"0.5.1\""));
        assert!(data.contains("\"exe\":\"C:\\\\test.exe\""));
        assert!(data.contains("\"sid\":\"S-1-5-21-1\""));
        assert!(data.contains("\"integrity_level\":\"MEDIUM\""));
        assert!(data.contains("\"enrichment_status\""));
        assert!(data.contains("\"cpu_percent\":null"));
    }

    #[test]
    fn ipc_metadata_is_bound_to_snapshot() {
        let p = sample_process();
        let meta = IpcMeta {
            sequence: 7,
            sensor_epoch: "123-456".into(),
            supervisor_pid: 456,
            sensor_pid: 789,
        };
        let data = encode(&[p], &[], EPOCH_TICKS + 100, Some(&meta)).unwrap();
        assert!(data.contains("\"protocol\":\"cd.sensor.ipc.v1\""));
        assert!(data.contains("\"sequence\":7"));
        assert!(data.contains("\"sensor_epoch\":\"123-456\""));
    }

    #[test]
    fn skipped_means_partial() {
        let data = encode(&[], &[open_failure(0, 87)], EPOCH_TICKS, None).unwrap();
        assert!(data.contains("\"partial\":true"));
        assert!(data.contains("\"reason\":\"SYSTEM_IDLE_UNQUERYABLE\",\"win32_error\":87"));
    }

    #[test]
    fn request_contract_rejects_replay_primitives() {
        let mut raw = [0u8; IPC_REQUEST_SIZE];
        raw[..4].copy_from_slice(&IPC_MAGIC);
        raw[4..6].copy_from_slice(&IPC_VERSION.to_le_bytes());
        raw[6..8].copy_from_slice(&IPC_OP_SNAPSHOT.to_le_bytes());
        raw[8..16].copy_from_slice(&9u64.to_le_bytes());
        let req = parse_ipc_request(&raw).unwrap();
        assert_eq!(req.sequence, 9);
        assert_eq!(req.op, IPC_OP_SNAPSHOT);

        raw[0] = b'X';
        assert!(parse_ipc_request(&raw).is_err());
    }

    #[test]
    fn output_bounds_are_enforced() {
        let too_many: Vec<_> = (0..=MAX_PROCESSES)
            .map(|pid| open_failure(pid as u32, 5))
            .collect();
        assert!(encode(&[], &too_many, EPOCH_TICKS, None).is_err());
    }
}
