#![windows_subsystem = "windows"]

use std::env;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, MAX_PATH};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, CreateRemoteThread, INFINITE, LPTHREAD_START_ROUTINE,
    PROCESS_INFORMATION, ResumeThread, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};
use windows_sys::Win32::System::WindowsProgramming::GetPrivateProfileStringW;
use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MessageBoxW};

/// Helper to convert Rust string to null-terminated UTF-16 vector
fn to_wstring(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Helper to show a MessageBox
fn show_error(message: &str, title: &str) {
    unsafe {
        let m_wide = to_wstring(message);
        let t_wide = to_wstring(title);
        MessageBoxW(
            ptr::null_mut(),
            m_wide.as_ptr(),
            t_wide.as_ptr(),
            MB_ICONERROR,
        );
    }
}

/// Injects a DLL into the target process
fn inject_dll(h_process: HANDLE, dll_path: &str) -> bool {
    unsafe {
        let dll_path_wide = to_wstring(dll_path);
        let size = dll_path_wide.len() * std::mem::size_of::<u16>();

        // 1. Allocate memory in the remote process
        let remote_mem = VirtualAllocEx(
            h_process,
            ptr::null(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            return false;
        }

        // 2. Write the DLL path to the allocated memory
        let mut bytes_written = 0;
        let write_result = WriteProcessMemory(
            h_process,
            remote_mem,
            dll_path_wide.as_ptr() as *const c_void,
            size,
            &mut bytes_written,
        );

        if write_result == FALSE {
            VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE);
            return false;
        }

        // 3. Get the address of LoadLibraryW from kernel32.dll
        // Note: kernel32.dll is loaded at the same address in every process
        let kernel32 = to_wstring("kernel32.dll");
        let h_kernel32 = GetModuleHandleW(kernel32.as_ptr());
        if h_kernel32.is_null() {
            VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE);
            return false;
        }

        let load_library_name = b"LoadLibraryW\0";
        let load_library_addr = GetProcAddress(h_kernel32, load_library_name.as_ptr());

        if load_library_addr.is_none() {
            VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE);
            return false;
        }

        // 4. Create a remote thread to execute LoadLibraryW
        let start_routine: LPTHREAD_START_ROUTINE = std::mem::transmute(load_library_addr);
        let h_thread = CreateRemoteThread(
            h_process,
            ptr::null(),
            0,
            start_routine,
            remote_mem,
            0,
            ptr::null_mut(),
        );

        if h_thread.is_null() {
            VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE);
            return false;
        }

        // 5. Wait for the thread to finish
        WaitForSingleObject(h_thread, INFINITE);

        // 6. Cleanup
        VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE);
        CloseHandle(h_thread);

        true
    }
}

fn main() {
    unsafe {
        // Get current executable directory
        let current_exe = env::current_exe().unwrap_or_default();
        let launcher_dir = current_exe.parent().unwrap_or(Path::new("."));

        // Define paths
        let config_path = launcher_dir.join("config.ini");
        // Note: Using the requested DLL name
        let dll_path = launcher_dir.join("hutao_minhook_ng.dll");

        // Check if DLL exists
        if !dll_path.exists() {
            show_error(&format!("DLL not found: {}", dll_path.display()), "Error");
            return;
        }

        // Read GamePath from config.ini
        let mut game_path_buf = [0u16; MAX_PATH as usize];
        let section = to_wstring("Settings");
        let key = to_wstring("GamePath");
        let default = to_wstring("");
        let config_path_str = to_wstring(config_path.to_str().unwrap_or(""));

        GetPrivateProfileStringW(
            section.as_ptr(),
            key.as_ptr(),
            default.as_ptr(),
            game_path_buf.as_mut_ptr(),
            MAX_PATH,
            config_path_str.as_ptr(),
        );

        let game_path_str = String::from_utf16_lossy(&game_path_buf);
        let game_path_trimmed = game_path_str.trim_matches('\0');

        if game_path_trimmed.is_empty() {
            show_error(
                "GamePath not found in config.ini or is empty.",
                "Config Error",
            );
            return;
        }

        let game_path = PathBuf::from(game_path_trimmed);
        if !game_path.exists() {
            show_error(
                &format!("Game executable not found at: {}", game_path_trimmed),
                "Config Error",
            );
            return;
        }

        let working_dir = game_path.parent().unwrap_or(Path::new("."));

        // Prepare structures for CreateProcess
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let game_path_wide = to_wstring(game_path_trimmed);
        let working_dir_wide = to_wstring(working_dir.to_str().unwrap_or(""));

        // Start the game process in SUSPENDED state
        let success = CreateProcessW(
            game_path_wide.as_ptr(),
            ptr::null_mut(), // Command line (optional if app name provided)
            ptr::null(),
            ptr::null(),
            FALSE,
            CREATE_SUSPENDED,
            ptr::null(),
            working_dir_wide.as_ptr(),
            &si,
            &mut pi,
        );

        if success == FALSE {
            show_error("Failed to start game process.", "Error");
            return;
        }

        // Inject the DLL
        if !inject_dll(pi.hProcess, dll_path.to_str().unwrap_or("")) {
            show_error("DLL Injection failed.", "Error");
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return;
        }

        // Resume the game thread
        ResumeThread(pi.hThread);

        // Cleanup handles
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}
