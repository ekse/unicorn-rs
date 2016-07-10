pub const SECOND_SCALE: u64 = 1000000;
pub const MILISECOND_SCALE: u64 = 1000;

// Architecture type
#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Arch {
    /// ARM architecture (including Thumb, Thumb-2)
    ARM = 1,
    /// ARM-64, also called AArch64
    ARM64,
    /// MIPS architecture
    MIPS,
    /// X86 architecture (including x86 & x86-64)
    X86,
    /// PowerPC architecture
    PPC,
    /// Sparc architecture
    SPARC,
    /// M68K architecture
    M68K,
}

// Mode type
#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Mode {
    LITTLE_ENDIAN = 0, // little-endian mode (default mode)
    // MODE_ARM = 0,    // 32-bit ARM
    MODE_16 = 1 << 1, // 16-bit mode (X86)
    MODE_32 = 1 << 2, // 32-bit mode (X86)
    MODE_64 = 1 << 3, // 64-bit mode (X86, PPC)
    THUMB = 1 << 4, // ARM's Thumb mode, including Thumb-2
    MCLASS = 1 << 5, // ARM's Cortex-M series
    V8 = 1 << 6, // ARMv8 A32 encodings for ARM
    // MICRO = 1 << 4, // MicroMips mode (MIPS)
    // MIPS3 = 1 << 5, // Mips III ISA
    // MIPS32R6 = 1 << 6, // Mips32r6 ISA
    // V9 = 1 << 4, // SparcV9 mode (Sparc)
    // QPX = 1 << 4, // Quad Processing eXtensions mode (PPC)
    BIG_ENDIAN = 1 << 30, /* big-endian mode
                           * UC_MODE_MIPS32 = UC_MODE_32,    // Mips32 ISA (Mips)
                           * UC_MODE_MIPS64 = UC_MODE_64,    // Mips64 ISA (Mips) */
}

// All type of errors encountered by Unicorn API.
// These are values returned by uc_errno()
#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Error {
    OK = 0, // No error: everything was fine
    NOMEM, // Out-Of-Memory error: uc_open(), uc_emulate()
    ARCH, // Unsupported architecture: uc_open()
    HANDLE, // Invalid handle
    MODE, // Invalid/unsupported mode: uc_open()
    VERSION, // Unsupported version (bindings)
    READ_UNMAPPED, // Quit emulation due to READ on unmapped memory: uc_emu_start()
    WRITE_UNMAPPED, // Quit emulation due to WRITE on unmapped memory: uc_emu_start()
    ETCH_UNMAPPED, // Quit emulation due to FETCH on unmapped memory: uc_emu_start()
    HOOK, // Invalid hook type: uc_hook_add()
    INSN_INVALID, // Quit emulation due to invalid instruction: uc_emu_start()
    MAP, // Invalid memory mapping: uc_mem_map()
    WRITE_PROT, // Quit emulation due to UC_MEM_WRITE_PROT violation: uc_emu_start()
    READ_PROT, // Quit emulation due to UC_MEM_READ_PROT violation: uc_emu_start()
    FETCH_PROT, // Quit emulation due to UC_MEM_FETCH_PROT violation: uc_emu_start()
    ARG, // Inavalid argument provided to uc_xxx function (See specific function API)
    READ_UNALIGNED, // Unaligned read
    WRITE_UNALIGNED, // Unaligned write
    FETCH_UNALIGNED, // Unaligned fetch
    HOOK_EXIST, // hook for this event already existed
}

bitflags! {
#[repr(C)]
pub flags Protection : u32 {
        const PROT_NONE = 0,
        const PROT_READ = 1,
        const PROT_WRITE = 2,
        const PROT_EXEC = 4,
        const PROT_ALL = 7,
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct MemRegion {
    /// The start address of the region (inclusive).
    begin: u64,
    /// The end address of the region (inclusive).
    end: u64,
    /// The memory permissions of the region.
    perms: Protection,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub enum MemType {
    READ = 16, // Memory is read from
    WRITE, // Memory is written to
    FETCH, // Memory is fetched
    READ_UNMAPPED, // Unmapped memory is read from
    WRITE_UNMAPPED, // Unmapped memory is written to
    MEM_FETCH_UNMAPPED, // Unmapped memory is fetched
    WRITE_PROT, // Write to write protected, but mapped, memory
    READ_PROT, // Read from read protected, but mapped, memory
    FETCH_PROT, // Fetch from non-executable, but mapped, memory
}

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum HookType {
    INTR = 1 << 0, // Hook all interrupt/syscall events
    INSN = 1 << 1, // Hook a particular instruction
    CODE = 1 << 2, // Hook a range of code
    BLOCK = 1 << 3, // Hook basic blocks
    MEM_READ_UNMAPPED = 1 << 4, // Hook for memory read on unmapped memory
    MEM_WRITE_UNMAPPED = 1 << 5, // Hook for invalid memory write events
    MEM_FETCH_UNMAPPED = 1 << 6, // Hook for invalid memory fetch for execution events
    MEM_READ_PROT = 1 << 7, // Hook for memory read on read-protected memory
    MEM_WRITE_PROT = 1 << 8, // Hook for memory write on write-protected memory
    MEM_FETCH_PROT = 1 << 9, // Hook for memory fetch on non-executable memory
    MEM_READ = 1 << 10, // Hook memory read events.
    MEM_WRITE = 1 << 11, // Hook memory write events.
    MEM_FETCH = 1 << 12, // Hook memory fetch for execution events
}

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum CodeHookType {
    CODE = 1 << 2, // Hook a range of code
    BLOCK = 1 << 3, // Hook basic blocks
}

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Query {
    /// The current hardware mode.
    MODE = 1,
    /// The page size used by the emulator
    PAGE_SIZE,
}
