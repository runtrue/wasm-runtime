#![no_main]
#![no_std]

use core::panic::PanicInfo;

#[repr(C)]
struct Ciovec {
    buffer: *const u8,
    length: u32,
}

#[link(wasm_import_module = "wasi_snapshot_preview1")]
unsafe extern "C" {
    fn args_sizes_get(argument_count: *mut u32, buffer_size: *mut u32) -> u16;
    fn args_get(arguments: *mut u32, buffer: *mut u8) -> u16;
    fn fd_write(fd: u32, iovecs: *const Ciovec, count: u32, written: *mut u32) -> u16;
}

#[link(wasm_import_module = "wasix_32v1")]
unsafe extern "C" {
    fn proc_snapshot() -> u16;
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() {
    let mut argument_count = 0;
    let mut argument_bytes = 0;
    if unsafe { args_sizes_get(&raw mut argument_count, &raw mut argument_bytes) } != 0
        || argument_count != 2
        || argument_bytes > 64
    {
        return;
    }

    let mut arguments = [0_u32; 2];
    let mut argument_buffer = [0_u8; 64];
    if unsafe { args_get(arguments.as_mut_ptr(), argument_buffer.as_mut_ptr()) } != 0 {
        return;
    }

    let mut value = 0_u64;
    let mut cursor = arguments[1] as *const u8;
    loop {
        let digit = unsafe { *cursor };
        if digit == 0 {
            break;
        }
        if !digit.is_ascii_digit() {
            return;
        }
        let Some(next) = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit - b'0')))
        else {
            return;
        };
        value = next;
        cursor = unsafe { cursor.add(1) };
    }

    // WASIX resumes at this call after restoring the Asyncify stack. This is
    // deliberately the first journal-aware host call made by the guest.
    if unsafe { proc_snapshot() } != 0 {
        return;
    }

    let mut output = [0_u8; 21];
    output[20] = b'\n';
    let mut start = 20;
    loop {
        start -= 1;
        output[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let iovec = Ciovec {
        buffer: output[start..].as_ptr(),
        length: (output.len() - start) as u32,
    };
    let mut written = 0;
    let _ = unsafe { fd_write(1, &raw const iovec, 1, &raw mut written) };
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
