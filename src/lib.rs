//! Bindings for the Unicorn emulator.
//!
//! Use the cpu_* helper functions to create an emulator instance of a specific processor type.
//!
//! # Example use
//!
//! ```rust
//! extern crate unicorn;
//!
//! use unicorn::Unicorn;
//!
//! fn main() {
//!    let x86_code32 : Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx
//!
//!    let mut emu = Unicorn::new(unicorn::Arch::X86, unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
//!    emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL);
//!    emu.mem_write(0x1000, &x86_code32);
//!    emu.reg_write_i32(unicorn::RegisterX86::ECX, -10);
//!    emu.reg_write_i32(unicorn::RegisterX86::EDX, -50);
//!
//!    emu.emu_start(0x1000, (0x1000 + x86_code32.len()) as u64, 10 * unicorn::SECOND_SCALE, 1000);
//!    assert_eq!(emu.reg_read_i32(unicorn::RegisterX86::ECX), Ok((-9)));
//!    assert_eq!(emu.reg_read_i32(unicorn::RegisterX86::EDX), Ok((-51)));
//! }
//! ```
//!
extern crate libunicorn_sys as ffi;
extern crate libc;

pub mod arm64_const;
pub mod arm_const;
pub mod m68k_const;
pub mod mips_const;
pub mod sparc_const;
pub mod x86_const;

use ffi::*;
use std::mem;
use std::collections::HashMap;

pub use arm64_const::*;
pub use arm_const::*;
pub use m68k_const::*;
pub use mips_const::*;
pub use sparc_const::*;
pub use unicorn_const::*;
pub use x86_const::*;
pub use ffi::{uc_handle, uc_hook};
pub use ffi::unicorn_const;

pub const BINDINGS_MAJOR: u32 = 1;
pub const BINDINGS_MINOR: u32 = 0;

extern "C" fn code_hook_proxy(_: uc_handle, address: u64, size: u32, user_data: *mut Hook) {
    let hook = unsafe { &mut *user_data };
    match hook.callback {
        HookCallback::Code(ref callback) => callback(unsafe { &mut *hook.unicorn }, address, size),
        _ => panic!("Unknown code callback"),
    }
}

extern "C" fn intr_hook_proxy(_: uc_handle, intno: u32, user_data: *mut Hook) {
    let hook = unsafe { &mut *user_data };
    match hook.callback {
        HookCallback::Intr(ref callback) => callback(unsafe { &mut *hook.unicorn }, intno),
        _ => panic!("Unknown intr callback"),
    }
}

extern "C" fn mem_hook_proxy(_: uc_handle,
                             mem_type: MemType,
                             address: u64,
                             size: usize,
                             value: i64,
                             user_data: *mut Hook)
                             -> bool {
    let hook = unsafe { &mut *user_data };
    match hook.callback {
        HookCallback::Mem(ref callback) => {
            callback(unsafe { &mut *hook.unicorn },
                     mem_type,
                     address,
                     size,
                     value)
        }
        _ => panic!("Unknown mem callback"),
    }
}

extern "C" fn insn_in_hook_proxy(_: uc_handle,
                                 port: u32,
                                 size: usize,
                                 user_data: *mut Hook)
                                 -> u32 {
    let hook = unsafe { &mut *user_data };
    match hook.callback {
        HookCallback::InsnIn(ref callback) => callback(unsafe { &mut *hook.unicorn }, port, size),
        _ => panic!("Unknown insnin callback"),
    }
}

extern "C" fn insn_out_hook_proxy(_: uc_handle,
                                  port: u32,
                                  size: usize,
                                  value: u32,
                                  user_data: *mut Hook) {
    let hook = unsafe { &mut *user_data };
    match hook.callback {
        HookCallback::InsnOut(ref callback) => {
            callback(unsafe { &mut *hook.unicorn }, port, size, value)
        }
        _ => panic!("Unknown instout callback"),
    }
}

extern "C" fn insn_sys_hook_proxy(_: uc_handle, user_data: *mut Hook) {
    let hook = unsafe { &mut *user_data };
    match hook.callback {
        HookCallback::InsnSys(ref callback) => callback(unsafe { &mut *hook.unicorn }),
        _ => panic!("Unknown sys callback"),
    }
}

enum HookCallback<'a> {
    Code(Box<Fn(&mut Unicorn, u64, u32) + 'a>),
    Intr(Box<Fn(&mut Unicorn, u32) + 'a>),
    Mem(Box<Fn(&mut Unicorn, MemType, u64, usize, i64) -> bool + 'a>),
    InsnIn(Box<Fn(&mut Unicorn, u32, usize) -> u32 + 'a>),
    InsnOut(Box<Fn(&mut Unicorn, u32, usize, u32) + 'a>),
    InsnSys(Box<Fn(&mut Unicorn) + 'a>),
}

struct Hook<'a> {
    callback: HookCallback<'a>,
    unicorn: *mut Unicorn<'a>,
}

/// Internal : A Unicorn emulator instance, use one of the Cpu structs instead.
pub struct Unicorn<'a> {
    handle: libc::size_t, // Opaque handle to uc_engine
    hooks: HashMap<uc_hook, Box<Hook<'a>>>, // for safe garbage collection?
}

/// Returns a tuple `(major, minor)` for the bindings version number.
pub fn bindings_version() -> (u32, u32) {
    (BINDINGS_MAJOR, BINDINGS_MINOR)
}

/// Returns a tuple `(major, minor)` for the unicorn version number.
pub fn unicorn_version() -> (u32, u32) {
    let mut major: u32 = 0;
    let mut minor: u32 = 0;
    let p_major: *mut u32 = &mut major;
    let p_minor: *mut u32 = &mut minor;
    unsafe {
        uc_version(p_major, p_minor);
    }
    (major, minor)
}


/// Returns `true` if the architecture is supported by this build of unicorn.
pub fn arch_supported(arch: Arch) -> bool {
    unsafe { uc_arch_supported(arch) }
}

impl<'a> Unicorn<'a> {
    /// Create a new instance of the unicorn engine for the specified architecture
    /// and hardware mode.
    pub fn new<'b>(arch: Arch, mode: Mode) -> Result<Unicorn<'b>, Error> {
        // Verify bindings compatibility with the core before going further.
        let (major, minor) = unicorn_version();
        if major != BINDINGS_MAJOR || minor != BINDINGS_MINOR {
            return Err(Error::VERSION);
        }

        let mut handle: libc::size_t = 0;
        let err = unsafe { uc_open(arch, mode, &mut handle) };
        if err == Error::OK {
            Ok(Unicorn {
                handle: handle,
                hooks: HashMap::default(),
            })
        } else {
            Err(err)
        }
    }

    /// Write an unsigned value register.
    ///
    /// Note : The register is defined as an i32 to be able to support the
    /// different register types (`RegisterX86`, `RegisterARM`, `RegisterMIPS` etc.).
    /// You need to cast the register with `as i32`.
    pub fn reg_write<R>(&mut self, reg: R, value: u64) -> Result<(), Error>
        where R: Into<i32>
    {
        let p_value: *const u64 = &value;
        let err = unsafe { uc_reg_write(self.handle, reg.into(), p_value as *const libc::c_void) };
        if err == Error::OK { Ok(()) } else { Err(err) }
    }

    /// Write a signed 32-bit value to a register.
    ///
    /// Note : The register is defined as an i32 to be able to support the
    /// different register types (`RegisterX86`, `RegisterARM`, `RegisterMIPS` etc.).
    pub fn reg_write_i32<R>(&mut self, reg: R, value: i32) -> Result<(), Error>
        where R: Into<i32>
    {
        let p_value: *const i32 = &value;
        let err = unsafe {
            uc_reg_write(self.handle,
                         reg.into() as libc::c_int,
                         p_value as *const libc::c_void)
        };
        if err == Error::OK { Ok(()) } else { Err(err) }
    }

    /// Read an unsigned value from a register.
    ///
    /// Note : The register is defined as an i32 to be able to support the
    /// different register types (`RegisterX86`, `RegisterARM`, `RegisterMIPS` etc.).
    pub fn reg_read<R>(&self, reg: R) -> Result<u64, Error>
        where R: Into<i32>
    {
        let mut value: u64 = 0;
        let p_value: *mut u64 = &mut value;
        let err = unsafe {
            uc_reg_read(self.handle,
                        reg.into() as libc::c_int,
                        p_value as *mut libc::c_void)
        };
        if err == Error::OK {
            Ok(value)
        } else {
            Err(err)
        }
    }

    /// Read a signed 32-bit value from a register.
    ///
    /// Note : The register is defined as an i32 to be able to support the
    /// different register types (`RegisterX86`, `RegisterARM`, `RegisterMIPS` etc.).
    pub fn reg_read_i32<R>(&self, reg: R) -> Result<i32, Error>
        where R: Into<i32>
    {
        let mut value: i32 = 0;
        let p_value: *mut i32 = &mut value;
        let err = unsafe {
            uc_reg_read(self.handle,
                        reg.into() as libc::c_int,
                        p_value as *mut libc::c_void)
        };
        if err == Error::OK {
            Ok(value)
        } else {
            Err(err)
        }
    }

    /// Map a memory region in the emulator at the specified address.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mem_map(&mut self,
                   address: u64,
                   size: libc::size_t,
                   perms: Protection)
                   -> Result<(), Error> {
        let err = unsafe { uc_mem_map(self.handle, address, size, perms.bits()) };
        if err == Error::OK { Ok(()) } else { Err(err) }
    }

    /// Unmap a memory region.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mem_unmap(&mut self, address: u64, size: libc::size_t) -> Result<(), Error> {
        let err = unsafe { uc_mem_unmap(self.handle, address, size) };
        if err == Error::OK { Ok(()) } else { Err(err) }
    }

    /// Write a range of bytes to memory at the specified address.
    pub fn mem_write(&self, address: u64, bytes: &[u8]) -> Result<(), Error> {
        let err = unsafe {
            uc_mem_write(self.handle,
                         address,
                         bytes.as_ptr(),
                         bytes.len() as libc::size_t)
        };
        if err == Error::OK { Ok(()) } else { Err(err) }
    }

    /// Read a range of bytes from memory at the specified address.
    pub fn mem_read(&self, address: u64, size: usize) -> Result<(Vec<u8>), Error> {
        let mut bytes: Vec<u8> = Vec::with_capacity(size);
        let err = unsafe {
            uc_mem_read(self.handle,
                        address,
                        bytes.as_mut_ptr(),
                        size as libc::size_t)
        };
        if err == Error::OK {
            unsafe {
                bytes.set_len(size);
            }
            Ok((bytes))
        } else {
            Err(err)
        }
    }

    /// Set the memory permissions for an existing memory region.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mem_protect(&mut self,
                       address: u64,
                       size: usize,
                       perms: Protection)
                       -> Result<(), Error> {
        let err =
            unsafe { uc_mem_protect(self.handle, address, size as libc::size_t, perms.bits()) };
        if err == Error::OK { Ok(()) } else { Err(err) }
    }

    /// Returns a vector with the memory regions that are mapped in the emulator.
    pub fn mem_regions(&self) -> Result<Vec<MemRegion>, Error> {
        // We make a copy of the MemRegion structs that are returned by uc_mem_regions()
        // as they have to be freed to the caller. It is simpler to make a copy and free()
        // the originals right away.
        let mut nb_regions: u32 = 0;
        let p_nb_regions: *mut u32 = &mut nb_regions;
        let p_regions: *const MemRegion = std::ptr::null();
        let pp_regions: *const *const MemRegion = &p_regions;
        let err = unsafe { uc_mem_regions(self.handle, pp_regions, p_nb_regions) };
        if err == Error::OK {
            let mut regions: Vec<MemRegion> = Vec::new();
            let mut i: isize = 0;
            while i < nb_regions as isize {
                unsafe {
                    let region: MemRegion = mem::transmute_copy(&*p_regions.offset(i));
                    regions.push(region);
                }
                i += 1;
            }
            unsafe { libc::free(*pp_regions as *mut libc::c_void) };
            Ok(regions)
        } else {
            Err(err)
        }
    }

    /// Emulate machine code for a specified duration.
    ///
    /// `begin` is the address where to start the emulation. The emulation stops if `until`
    /// is hit. `timeout` specifies a duration in microseconds after which the emulation is
    /// stopped (infinite execution if set to 0). `count` is the maximum number of instructions
    /// to emulate (emulate all the available instructions if set to 0).
    pub fn emu_start(&mut self,
                     begin: u64,
                     until: u64,
                     timeout: u64,
                     count: usize)
                     -> Result<(), Error> {
        let err =
            unsafe { uc_emu_start(self.handle, begin, until, timeout, count as libc::size_t) };
        if err == Error::OK { Ok(()) } else { Err(err) }
    }

    /// Stop the emulation.
    ///
    /// This is usually called from callback function in hooks.
    /// NOTE: For now, this will stop the execution only after the current block.
    pub fn emu_stop(&mut self) -> Result<(), Error> {
        let err = unsafe { uc_emu_stop(self.handle) };
        if err == Error::OK { Ok(()) } else { Err(err) }
    }

    /// Add a code hook.
    pub fn add_code_hook<F>(&mut self,
                            hook_type: CodeHookType,
                            begin: u64,
                            end: u64,
                            callback: F)
                            -> Result<uc_hook, Error>
        where F: Fn(&mut Unicorn, u64, u32) + 'a
    {
        let mut hook: uc_hook = 0;
        let p_hook: *mut libc::size_t = &mut hook;

        let user_data = Box::new(Hook {
            unicorn: self as *mut _,
            callback: HookCallback::Code(Box::new(callback)),
        });
        let p_user_data: *mut libc::size_t = unsafe { mem::transmute(&*user_data) };
        let _callback: libc::size_t = code_hook_proxy as usize;

        let err = unsafe {
            uc_hook_add(self.handle,
                        p_hook,
                        mem::transmute(hook_type),
                        _callback,
                        p_user_data,
                        begin,
                        end)
        };
        if err == Error::OK {
            self.hooks.insert(hook, user_data);
            Ok(hook)
        } else {
            Err(err)
        }
    }

    /// Add an interrupt hook.
    pub fn add_intr_hook<F>(&mut self, callback: F) -> Result<uc_hook, Error>
        where F: Fn(&mut Unicorn, u32) + 'a
    {
        let mut hook: uc_hook = 0;
        let p_hook: *mut libc::size_t = &mut hook;

        let user_data = Box::new(Hook {
            unicorn: self as *mut _,
            callback: HookCallback::Intr(Box::new(callback)),
        });
        let p_user_data: *mut libc::size_t = unsafe { mem::transmute(&*user_data) };
        let _callback: libc::size_t = intr_hook_proxy as usize;

        let err = unsafe {
            uc_hook_add(self.handle,
                        p_hook,
                        HookType::INTR,
                        _callback,
                        p_user_data,
                        0,
                        0)
        };

        if err == Error::OK {
            self.hooks.insert(hook, user_data);
            Ok(hook)
        } else {
            Err(err)
        }
    }

    /// Add a memory hook.
    pub fn add_mem_hook<F>(&mut self,
                           hook_type: MemHookType,
                           begin: u64,
                           end: u64,
                           callback: F)
                           -> Result<uc_hook, Error>
        where F: Fn(&mut Unicorn, MemType, u64, usize, i64) -> bool + 'a
    {
        let mut hook: uc_hook = 0;
        let p_hook: *mut libc::size_t = &mut hook;

        let user_data = Box::new(Hook {
            unicorn: self as *mut _,
            callback: HookCallback::Mem(Box::new(callback)),
        });
        let p_user_data: *mut libc::size_t = unsafe { mem::transmute(&*user_data) };
        let _callback: libc::size_t = mem_hook_proxy as usize;

        let err = unsafe {
            uc_hook_add(self.handle,
                        p_hook,
                        mem::transmute(hook_type),
                        _callback,
                        p_user_data,
                        begin,
                        end)
        };

        if err == Error::OK {
            self.hooks.insert(hook, user_data);
            Ok(hook)
        } else {
            Err(err)
        }
    }

    /// Add an "in" instruction hook.
    pub fn add_insn_in_hook<F>(&mut self, callback: F) -> Result<uc_hook, Error>
        where F: Fn(&mut Unicorn, u32, usize) -> u32 + 'a
    {
        let mut hook: uc_hook = 0;
        let p_hook: *mut libc::size_t = &mut hook;

        let user_data = Box::new(Hook {
            unicorn: self as *mut _,
            callback: HookCallback::InsnIn(Box::new(callback)),
        });
        let p_user_data: *mut libc::size_t = unsafe { mem::transmute(&*user_data) };
        let _callback: libc::size_t = insn_in_hook_proxy as usize;

        let err = unsafe {
            uc_hook_add(self.handle,
                        p_hook,
                        HookType::INSN,
                        _callback,
                        p_user_data,
                        0,
                        0,
                        x86_const::InsnX86::IN)
        };

        if err == Error::OK {
            self.hooks.insert(hook, user_data);
            Ok(hook)
        } else {
            Err(err)
        }
    }

    /// Add an "out" instruction hook.
    pub fn add_insn_out_hook<F>(&mut self, callback: F) -> Result<uc_hook, Error>
        where F: Fn(&mut Unicorn, u32, usize, u32) + 'a
    {
        let mut hook: uc_hook = 0;
        let p_hook: *mut libc::size_t = &mut hook;

        let user_data = Box::new(Hook {
            unicorn: self as *mut _,
            callback: HookCallback::InsnOut(Box::new(callback)),
        });
        let p_user_data: *mut libc::size_t = unsafe { mem::transmute(&*user_data) };
        let _callback: libc::size_t = insn_out_hook_proxy as usize;

        let err = unsafe {
            uc_hook_add(self.handle,
                        p_hook,
                        HookType::INSN,
                        _callback,
                        p_user_data,
                        0,
                        0,
                        x86_const::InsnX86::OUT)
        };

        if err == Error::OK {
            self.hooks.insert(hook, user_data);
            Ok(hook)
        } else {
            Err(err)
        }
    }

    /// Add a "syscall" or "sysenter" instruction hook.
    pub fn add_insn_sys_hook<F>(&mut self,
                                insn_type: InsnSysX86,
                                begin: u64,
                                end: u64,
                                callback: F)
                                -> Result<uc_hook, Error>
        where F: Fn(&mut Unicorn) + 'a
    {
        let mut hook: uc_hook = 0;
        let p_hook: *mut libc::size_t = &mut hook;

        let user_data = Box::new(Hook {
            unicorn: self as *mut _,
            callback: HookCallback::InsnSys(Box::new(callback)),
        });
        let p_user_data: *mut libc::size_t = unsafe { mem::transmute(&*user_data) };
        let _callback: libc::size_t = insn_sys_hook_proxy as usize;

        let err = unsafe {
            uc_hook_add(self.handle,
                        p_hook,
                        HookType::INSN,
                        _callback,
                        p_user_data,
                        begin,
                        end,
                        insn_type)
        };

        if err == Error::OK {
            self.hooks.insert(hook, user_data);
            Ok(hook)
        } else {
            Err(err)
        }
    }

    /// Remove a hook.
    ///
    /// `hook` is the value returned by either `add_code_hook` or `add_mem_hook`.
    pub fn remove_hook(&mut self, hook: uc_hook) -> Result<(), Error> {
        let err = unsafe { uc_hook_del(self.handle, hook) } as Error;
        self.hooks.remove(&hook);
        if err == Error::OK { Ok(()) } else { Err(err) }

    }

    /// Return the last error code when an API function failed.
    ///
    /// Like glibc errno(), this function might not retain its old value once accessed.
    pub fn errno(&self) -> Error {
        unsafe { uc_errno(self.handle) }
    }

    /// Query the internal status of the engine.
    ///
    /// Supported queries :
    ///
    /// - `Query::PAGE_SIZE` : the page size used by the emulator.
    /// - `Query::MODE` : the current hardware mode.
    pub fn query(&self, query: Query) -> Result<usize, Error> {
        let mut result: libc::size_t = 0;
        let p_result: *mut libc::size_t = &mut result;
        let err = unsafe { uc_query(self.handle, query, p_result) };
        if err == Error::OK {
            Ok(result)
        } else {
            Err(err)
        }
    }

    // x86 only, read Model-specific register (msr,rdmsr)
    pub fn x86_msr_read(&self, msr: X86MSR) -> Result<u64, Error> {
        let mut value = uc_x86_msr {
            msr: msr as u32,
            value: 0,
        };
        let p_value: *mut uc_x86_msr = &mut value;
        let err = unsafe {
            uc_reg_read(self.handle,
                        (RegisterX86::MSR as i32) as libc::c_int,
                        p_value as *mut libc::c_void)
        };
        if err == Error::OK {
            Ok(value.value)
        } else {
            Err(err)
        }
    }

    // x86 only, write Model-specific register (msr,wrmsr)
    pub fn x86_msr_write(&mut self, msr: X86MSR, value: u64) -> Result<(), Error> {
        let v = uc_x86_msr {
            msr: msr as u32,
            value: value,
        };
        let p_value: *const uc_x86_msr = &v;
        let err = unsafe {
            uc_reg_write(self.handle,
                         RegisterX86::MSR as i32,
                         p_value as *const libc::c_void)
        };
        if err == Error::OK { Ok(()) } else { Err(err) }
    }
}

impl<'a> Drop for Unicorn<'a> {
    fn drop(&mut self) {
        unsafe { uc_close(self.handle) };
    }
}
