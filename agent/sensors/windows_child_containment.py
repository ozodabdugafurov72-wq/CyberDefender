"""Atomic Windows child ownership. No create-then-assign fallback.

Windows 10+ PROC_THREAD_ATTRIBUTE_JOB_LIST assigns the noninheritable,
kill-on-close Job Object as part of CreateProcessW. Only pipe handles are
inherited. Failure to establish the job prevents optional sensor execution.
"""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
import os
import subprocess
import hashlib
from contextlib import contextmanager
from pathlib import Path


def sensor_environment(nonce: str, supervisor_pid: int) -> dict[str, str]:
    env = {"CYBERDEFENDER_SENSOR_LAUNCH_NONCE": nonce,
           "CYBERDEFENDER_SENSOR_SUPERVISOR_PID": str(supervisor_pid)}
    if os.name == "nt":
        import win32api
        # Resolve the OS directory through Windows, not inherited variables.
        windows = win32api.GetWindowsDirectory()
        env.update(SYSTEMROOT=windows, WINDIR=windows)
    return env


@contextmanager
def verified_binary(path: Path, expected: str):
    """Deny concurrent write/delete while hashing and creating the image."""
    import win32con, win32file
    handle = None
    try:
        handle = win32file.CreateFile(str(path), win32con.GENERIC_READ, win32con.FILE_SHARE_READ,
                                     None, win32con.OPEN_EXISTING, win32con.FILE_ATTRIBUTE_NORMAL, None)
        digest = hashlib.sha256()
        size = win32file.GetFileSize(handle)
        if not 0 < size <= 64 * 1024 * 1024:
            raise ContainmentError("BINARY_SIZE_REJECTED")
        remaining = size
        while remaining:
            _, data = win32file.ReadFile(handle, min(1024 * 1024, remaining))
            if not data: raise ContainmentError("BINARY_READ_FAILED")
            remaining -= len(data); digest.update(data)
        if digest.hexdigest() != expected:
            raise ContainmentError("BINARY_PIN_MISMATCH")
        yield
    finally:
        if handle is not None: handle.Close()


class ContainmentError(OSError):
    pass


class ContainedProcess:
    def __init__(self, handle, job, pid, stdin, stdout):
        self._handle, self._job, self.pid = handle, job, pid
        self.stdin, self.stdout = stdin, stdout
        self.returncode = None

    def poll(self):
        import win32event, win32process
        if self.returncode is None and win32event.WaitForSingleObject(self._handle, 0) == 0:
            self.returncode = win32process.GetExitCodeProcess(self._handle)
        return self.returncode

    def wait(self, timeout=None):
        import win32event
        result = win32event.WaitForSingleObject(self._handle, 0xFFFFFFFF if timeout is None else int(timeout * 1000))
        if result == 258:
            raise subprocess.TimeoutExpired("contained sensor", timeout)
        if result != 0:
            raise ContainmentError("CHILD_WAIT_FAILED")
        return self.poll()

    def kill(self):
        import win32job
        win32job.TerminateJobObject(self._job, 1)

    def release(self):
        if self.poll() is None:
            raise ContainmentError("CHILD_EXIT_NOT_VERIFIED")
        self._handle.Close()
        self._job.Close()


def launch_contained(command: list[str], env: dict[str, str]) -> ContainedProcess:
    if os.name != "nt":
        raise ContainmentError("WINDOWS_CONTAINMENT_REQUIRED")
    import msvcrt
    import pywintypes
    import win32job

    class SI(C.Structure):
        _fields_ = [("cb", W.DWORD), ("lpReserved", W.LPWSTR), ("lpDesktop", W.LPWSTR),
                    ("lpTitle", W.LPWSTR), ("dwX", W.DWORD), ("dwY", W.DWORD),
                    ("dwXSize", W.DWORD), ("dwYSize", W.DWORD), ("dwXCountChars", W.DWORD),
                    ("dwYCountChars", W.DWORD), ("dwFillAttribute", W.DWORD), ("dwFlags", W.DWORD),
                    ("wShowWindow", W.WORD), ("cbReserved2", W.WORD), ("lpReserved2", C.c_void_p),
                    ("hStdInput", W.HANDLE), ("hStdOutput", W.HANDLE), ("hStdError", W.HANDLE)]

    class SIX(C.Structure):
        _fields_ = [("StartupInfo", SI), ("lpAttributeList", C.c_void_p)]

    class PI(C.Structure):
        _fields_ = [("hProcess", W.HANDLE), ("hThread", W.HANDLE), ("dwProcessId", W.DWORD), ("dwThreadId", W.DWORD)]

    k = C.WinDLL("kernel32", use_last_error=True)
    init = k.InitializeProcThreadAttributeList
    init.argtypes = [C.c_void_p, W.DWORD, W.DWORD, C.POINTER(C.c_size_t)]
    init.restype = W.BOOL
    update = k.UpdateProcThreadAttribute
    update.argtypes = [C.c_void_p, W.DWORD, C.c_size_t, C.c_void_p, C.c_size_t, C.c_void_p, C.c_void_p]
    update.restype = W.BOOL
    delete = k.DeleteProcThreadAttributeList
    delete.argtypes = [C.c_void_p]
    delete.restype = None
    create = k.CreateProcessW
    create.argtypes = [W.LPCWSTR, W.LPWSTR, C.c_void_p, C.c_void_p, W.BOOL, W.DWORD,
                       C.c_void_p, W.LPCWSTR, C.POINTER(SIX), C.POINTER(PI)]
    create.restype = W.BOOL
    job = win32job.CreateJobObject(None, "")
    fds = []
    attributes = None
    process = None
    try:
        limits = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
        limits["BasicLimitInformation"]["LimitFlags"] = win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, limits)
        # The venv Python fixture may itself use a launcher child. Native Rust
        # does not. All descendants remain in the job, with no breakaway flag.
        r_in, w_in = os.pipe(); fds.extend((r_in, w_in))
        r_out, w_out = os.pipe(); fds.extend((r_out, w_out))
        err = os.open(os.devnull, os.O_WRONLY); fds.append(err)
        handles = (W.HANDLE * 3)(*[msvcrt.get_osfhandle(fd) for fd in (r_in, w_out, err)])
        for h in handles:
            os.set_handle_inheritable(h, True)
        size = C.c_size_t()
        init(None, 2, 0, C.byref(size))
        if not size.value or size.value > 65536:
            raise ContainmentError("ATTRIBUTE_SIZE_INVALID")
        attributes = C.create_string_buffer(size.value)
        if not init(attributes, 2, 0, C.byref(size)):
            attributes = None
            raise ContainmentError("ATTRIBUTE_INIT_FAILED")
        jobs = (W.HANDLE * 1)(int(job))
        for key, value in ((0x00020002, handles), (0x0002000D, jobs)):
            if not update(attributes, 0, key, value, C.sizeof(value), None, None):
                raise ContainmentError("ATOMIC_CONTAINMENT_UNAVAILABLE")
        si = SIX(); si.StartupInfo.cb = C.sizeof(SIX)
        si.StartupInfo.dwFlags = 0x100  # STARTF_USESTDHANDLES
        si.StartupInfo.hStdInput, si.StartupInfo.hStdOutput, si.StartupInfo.hStdError = handles
        si.lpAttributeList = C.cast(attributes, C.c_void_p)
        pi = PI()
        block = C.create_unicode_buffer("\0".join(f"{key}={value}" for key, value in sorted(env.items())) + "\0\0")
        cmdline = C.create_unicode_buffer(subprocess.list2cmdline(command))
        flags = 0x00080000 | 0x00000400 | 0x08000000  # extended, Unicode, no window
        if not create(command[0], cmdline, None, None, True, flags, block, None, C.byref(si), C.byref(pi)):
            raise ContainmentError("CONTAINED_CREATE_FAILED")
        ph = pywintypes.HANDLE(pi.hProcess)
        pywintypes.HANDLE(pi.hThread).Close()
        process = ContainedProcess(ph, job, pi.dwProcessId, None, None)
        process.stdin = os.fdopen(w_in, "wb", buffering=0); fds.remove(w_in)
        process.stdout = os.fdopen(r_out, "rb", buffering=0); fds.remove(r_out)
        return process
    except BaseException:
        # Closing this sole job handle also contains failure during pipe wrapping.
        job.Close()
        if process is not None:
            process.wait(timeout=2)
            process._handle.Close()
            for stream in (process.stdin, process.stdout):
                if stream is not None: stream.close()
        raise
    finally:
        if attributes is not None: delete(attributes)
        for fd in fds: os.close(fd)
