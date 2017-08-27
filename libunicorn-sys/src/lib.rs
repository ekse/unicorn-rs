extern crate libc;
#[macro_use]
extern crate bitflags;

pub mod unicorn_const;

use std::ffi::CStr;
use std::os::raw::c_char;
use unicorn_const::{Arch, MemRegion, Mode, Error, HookType, Query};

#[allow(non_camel_case_types)]
pub type uc_handle = libc::size_t;
#[allow(non_camel_case_types)]
pub type uc_hook = libc::size_t;

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct uc_x86_msr {
    pub msr: u32,
    pub value: u64,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct uc_x86_mmr {
    pub selector: u16,  /* not used by GDTR and IDTR */
    pub base: u64, /* handle 32 or 64 bit CPUs */
    pub limit: u32,
    pub flags: u32, /* not used by GDTR and IDTR */
}

extern "C" {
    pub fn uc_version(major: *const u32, minor: *const u32) -> u32;
    pub fn uc_arch_supported(arch: Arch) -> bool;
    pub fn uc_open(arch: Arch, mode: Mode, engine: *mut uc_handle) -> Error;
    pub fn uc_close(engine: uc_handle) -> Error;
    pub fn uc_errno(engine: uc_handle) -> Error;
    pub fn uc_strerror(error_code: Error) -> *const c_char;
    pub fn uc_reg_write(engine: uc_handle,
                        regid: libc::c_int,
                        value: *const libc::c_void)
                        -> Error;
    pub fn uc_reg_read(engine: uc_handle, regid: libc::c_int, value: *mut libc::c_void) -> Error;
    pub fn uc_mem_write(engine: uc_handle,
                        address: u64,
                        bytes: *const u8,
                        size: libc::size_t)
                        -> Error;
    pub fn uc_mem_read(engine: uc_handle,
                       address: u64,
                       bytes: *mut u8,
                       size: libc::size_t)
                       -> Error;
    pub fn uc_mem_map(engine: uc_handle, address: u64, size: libc::size_t, perms: u32) -> Error;
    pub fn uc_mem_unmap(engine: uc_handle, address: u64, size: libc::size_t) -> Error;
    pub fn uc_mem_protect(engine: uc_handle,
                          address: u64,
                          size: libc::size_t,
                          perms: u32)
                          -> Error;
    pub fn uc_mem_regions(engine: uc_handle,
                          regions: *const *const MemRegion,
                          count: *mut u32)
                          -> Error;
    pub fn uc_emu_start(engine: uc_handle,
                        begin: u64,
                        until: u64,
                        timeout: u64,
                        count: libc::size_t)
                        -> Error;
    pub fn uc_emu_stop(engine: uc_handle) -> Error;
    pub fn uc_hook_add(engine: uc_handle,
                       hook: *mut uc_hook,
                       hook_type: HookType,
                       callback: libc::size_t,
                       user_data: *mut libc::size_t,
                       begin: u64,
                       end: u64,
                       ...)
                       -> Error;
    pub fn uc_hook_del(engine: uc_handle, hook: uc_hook) -> Error;
    pub fn uc_query(engine: uc_handle, query_type: Query, result: *mut libc::size_t) -> Error;
}


impl Error {
    pub fn msg(&self) -> String {
        error_msg(*self)
    }
}

/// Returns a string for the specified error code.
pub fn error_msg(error: Error) -> String {
    unsafe { CStr::from_ptr(uc_strerror(error)).to_string_lossy().into_owned() }
}
