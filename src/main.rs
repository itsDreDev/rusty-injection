use core::ffi::c_void;
use faithe::memory::MemoryProtection;
use faithe::process::*;
use faithe::types::access_rights::PROCESS_ALL_ACCESS;
use faithe::types::allocation_types::{MEM_COMMIT, MEM_RESERVE};

use windows::Win32::{Foundation::HANDLE, System::LibraryLoader::GetProcAddress};

pub type DWORD = u32;
pub type DWORD_PTR = usize;
pub type LPVOID = *mut c_void;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Threading::{CreateRemoteThread, LPTHREAD_START_ROUTINE};

fn get_proc(proc_name: &str) -> ProcessEntry {
    Processes::new()
        .unwrap()
        .find(|p| p.sz_exe_file == proc_name)
        .unwrap()
}

fn get_processes(proc_name: &str) -> Vec<ProcessEntry> {
    let mut processes: Vec<ProcessEntry> = Vec::new();
    let process = Processes::new().unwrap();
    let proc = process.filter(|p| p.sz_exe_file == proc_name);
    for p in proc {
        processes.push(p);
    }
    processes
}

fn open_processes(processes: Vec<ProcessEntry>) -> Vec<Process> {
    let mut handles: Vec<Process> = Vec::new();
    for process in processes {
        let handle = process.open(false, PROCESS_ALL_ACCESS).unwrap();
        handles.push(handle);
    }
    handles
}

fn get_uninjected_processes(processes: Vec<Process>, dll_name: &str) -> Vec<Process> {
    let mut uninjected: Vec<Process> = Vec::new();
    for p in processes {
        let dll = p.modules().unwrap().find(|m| m.sz_module == dll_name);
        if dll.is_none() {
            println!("not injected");
            uninjected.push(p);
        }
    }
    uninjected
}

fn inject_processes(handles: Vec<Process>, dll_path: &str, proc_name: &str) {
    for handle in handles {
        unsafe {
            inject(handle, dll_path, proc_name);
        }
    }
}

unsafe fn inject(p: Process, dll_path: &str, proc_name: &str) {
    let k32 = p
        .modules()
        .unwrap()
        .find(|m| m.sz_module == "kernel32.dll")
        .unwrap();
    let base = p
        .modules()
        .unwrap()
        .find(|m| m.sz_module == proc_name)
        .unwrap();

    let pc_str_load_lib = pc_str!("LoadLibraryA");
    let win_hdl = windows::Win32::Foundation::HINSTANCE(k32.h_module.0 as isize);
    let load_lib_address = GetProcAddress(win_hdl, pc_str_load_lib).unwrap();

    let dll_path_size = dll_path.as_bytes().len();

    let dll_addr = p
        .allocate(
            0,
            dll_path_size,
            MEM_RESERVE | MEM_COMMIT,
            MemoryProtection::READ_WRITE_EXECUTE,
        )
        .unwrap();
    println!(
        "LoadLibraryA address: {:p}",
        load_lib_address as *mut c_void
    );
    println!("Base address: {:x}", base.mod_base_addr);
    println!("Dll address: {:x}", dll_addr);
    println!("Dll path: {}", dll_path);
    println!("Dll path size: {}", dll_path_size);
    println!("Dll path bytes: {:?}", dll_path.as_bytes());

    let _res = p.write_buf(dll_addr, dll_path.as_bytes());

    let thread_handle = {
        type StartRoutine = extern "system" fn(LPVOID) -> DWORD;
        let start_routine: StartRoutine = std::mem::transmute(load_lib_address);
        let p_h = p.handle().0;
        let win_h = windows::Win32::Foundation::HANDLE(p_h as isize);

        create_remote_thread(
            win_h,
            None,
            0,
            Some(start_routine),
            Some(dll_addr as *const c_void),
            0,
            None,
        )
        /* let thread = p
            .create_remote_thread(start_routine as usize, dll_addr as *const usize)
            .unwrap();
        println!("Thread handle: {:?}", thread); */
    };
    close_handle(thread_handle);
}

fn main() {
    let dll_path = std::env::var("dll_path").expect("You must provide a dll path");
    let process_name = std::env::var("process_name").expect("You must give a process name");

    let path = std::path::Path::new(&dll_path);
    if !path.exists() {
        panic!("The DLL doesn't exist at {}", dll_path);
    }
    let dll_name = path.file_name();
    if dll_name.is_none() {
        panic!("The DLL doesn't have a name");
    }
    let dll_name = dll_name.unwrap().to_str().unwrap();

    println!("Injection for {} {} {}", process_name, dll_path, dll_name);

    println!("Getting processes");
    let proc = get_proc(&process_name);
    println!("Found process {}", proc.sz_exe_file);

    println!("Finding processes...");
    let processes = get_processes(&process_name);
    if processes.is_empty() {
        panic!("No processes found with the name {}", process_name);
    }
    println!("Found {} processes", processes.len());

    let processes = open_processes(processes);
    println!("Opened {} processes", processes.len());

    let uninjected_processes = get_uninjected_processes(processes, &dll_name);
    if uninjected_processes.is_empty() {
        println!("All processes are already injected with {}", dll_name);
    }
    println!("Found {} uninjected processes", uninjected_processes.len());
    inject_processes(uninjected_processes, &dll_path, &process_name);
    println!("Complete");
}

#[macro_export]
macro_rules! pc_str {
    ($($str:tt),*) => {
        windows::core::PCSTR(concat!($($str),*, '\x00').as_ptr() as _)
    };
}

fn create_remote_thread(
    process: HANDLE,
    thread_attributes: Option<*const SECURITY_ATTRIBUTES>,
    stack_size: usize,
    start_address: LPTHREAD_START_ROUTINE,
    parameter: Option<*const c_void>,
    creation_flags: u32,
    thread_id: Option<*mut u32>,
) -> HANDLE {
    let handle = unsafe {
        CreateRemoteThread(
            process,
            thread_attributes,
            stack_size,
            start_address,
            parameter,
            creation_flags,
            thread_id,
        )
    };

    handle.unwrap()
}

fn close_handle(handle: HANDLE) {
    let _res = unsafe { CloseHandle(handle) };
}
