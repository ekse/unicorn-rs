extern crate unicorn;

use unicorn::{Cpu, CpuX86, CpuARM, CpuMIPS};

#[test]
fn emulate_x86() {
    let x86_code32: Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx

    let mut emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.reg_write(unicorn::RegisterX86::EAX, 123), Ok(()));
    assert_eq!(emu.reg_read(unicorn::RegisterX86::EAX), Ok((123)));

    // Attempt to write to memory before mapping it.
    assert_eq!(emu.mem_write(0x1000, &x86_code32),
               (Err(unicorn::Error::WRITE_UNMAPPED)));

    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));
    assert_eq!(emu.mem_read(0x1000, x86_code32.len()),
               Ok(x86_code32.clone()));

    assert_eq!(emu.reg_write(unicorn::RegisterX86::ECX, 10), Ok(()));
    assert_eq!(emu.reg_write(unicorn::RegisterX86::EDX, 50), Ok(()));

    assert_eq!(emu.emu_start(0x1000,
                             (0x1000 + x86_code32.len()) as u64,
                             10 * unicorn::SECOND_SCALE,
                             1000),
               Ok(()));
    assert_eq!(emu.reg_read(unicorn::RegisterX86::ECX), Ok((11)));
    assert_eq!(emu.reg_read(unicorn::RegisterX86::EDX), Ok((49)));
}



#[test]
fn emulate_x86_negative_values() {
    let x86_code32: Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx

    let emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");

    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));

    assert_eq!(emu.reg_write_i32(unicorn::RegisterX86::ECX, -10), Ok(()));
    assert_eq!(emu.reg_write_i32(unicorn::RegisterX86::EDX, -50), Ok(()));

    assert_eq!(emu.emu_start(0x1000,
                             (0x1000 + x86_code32.len()) as u64,
                             10 * unicorn::SECOND_SCALE,
                             1000),
               Ok(()));
    assert_eq!(emu.reg_read_i32(unicorn::RegisterX86::ECX), Ok((-9)));
    assert_eq!(emu.reg_read_i32(unicorn::RegisterX86::EDX), Ok((-51)));
}

#[test]
fn x86_code_callback() {
    #[derive(PartialEq, Debug)]
    struct CodeExpectation(u64, u32);
    let expects = vec![CodeExpectation(0x1000, 1), CodeExpectation(0x1001, 1)];
    let codes: Vec<CodeExpectation> = Vec::new();
    let codes_cell = ::std::rc::Rc::new(::std::cell::RefCell::new(codes));

    let callback_codes = codes_cell.clone();
    let callback = move |_: &unicorn::Unicorn, address: u64, size: u32| {
        let mut codes = callback_codes.borrow_mut();
        codes.push(CodeExpectation(address, size));
    };

    let x86_code32: Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx

    let mut emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));

    let hook = emu.add_code_hook(unicorn::CodeHookType::CODE, 0x1000, 0x2000, callback)
        .expect("failed to add code hook");
    assert_eq!(emu.emu_start(0x1000, 0x1002, 10 * unicorn::SECOND_SCALE, 1000),
               Ok(()));
    assert_eq!(expects, *codes_cell.borrow());
    assert_eq!(emu.remove_hook(hook), Ok(()));
}

#[test]
fn x86_intr_callback() {
    #[derive(PartialEq, Debug)]
    struct IntrExpectation(u32);
    let expect = IntrExpectation(0x80);
    let intr_cell = ::std::rc::Rc::new(::std::cell::RefCell::new(IntrExpectation(0)));

    let callback_intr = intr_cell.clone();
    let callback = move |_: &unicorn::Unicorn, intno: u32| {
        *callback_intr.borrow_mut() = IntrExpectation(intno);
    };

    let x86_code32: Vec<u8> = vec![0xcd, 0x80]; // INT 0x80;

    let mut emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));

    let hook = emu.add_intr_hook(callback)
        .expect("failed to add intr hook");

    assert_eq!(emu.emu_start(0x1000,
                             0x1000 + x86_code32.len() as u64,
                             10 * unicorn::SECOND_SCALE,
                             1000),
               Ok(()));
    assert_eq!(expect, *intr_cell.borrow());
    assert_eq!(emu.remove_hook(hook), Ok(()));
}

#[test]
fn x86_mem_callback() {
    #[derive(PartialEq, Debug)]
    struct MemExpectation(unicorn::MemType, u64, usize, i64);
    let expects = vec![MemExpectation(unicorn::MemType::WRITE, 0x2000, 4, 0xdeadbeef),
                       MemExpectation(unicorn::MemType::READ_UNMAPPED, 0x10000, 4, 0)];
    let mems: Vec<MemExpectation> = Vec::new();
    let mems_cell = ::std::rc::Rc::new(::std::cell::RefCell::new(mems));

    let callback_mems = mems_cell.clone();
    let callback = move |_: &unicorn::Unicorn,
                         mem_type: unicorn::MemType,
                         address: u64,
                         size: usize,
                         value: i64| {
        let mut mems = callback_mems.borrow_mut();
        mems.push(MemExpectation(mem_type, address, size, value));
        false
    };

    // mov eax, 0xdeadbeef;
    // mov [0x2000], eax;
    // mov eax, [0x10000];
    let x86_code32: Vec<u8> = vec![0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xA3, 0x00, 0x20, 0x00, 0x00,
                                   0xA1, 0x00, 0x00, 0x01, 0x00];

    let mut emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));

    let hook = emu.add_mem_hook(unicorn::MemHookType::MEM_ALL, 0, std::u64::MAX, callback)
        .expect("failed to add memory hook");
    assert_eq!(emu.reg_write(unicorn::RegisterX86::EAX, 0x123), Ok(()));
    assert_eq!(emu.emu_start(0x1000,
                             0x1000 + x86_code32.len() as u64,
                             10 * unicorn::SECOND_SCALE,
                             0x1000),
               Err((unicorn::Error::READ_UNMAPPED)));

    assert_eq!(expects, *mems_cell.borrow());
    assert_eq!(emu.remove_hook(hook), Ok(()));
}

#[test]
fn emulate_arm() {
    let arm_code32: Vec<u8> = vec![0x83, 0xb0]; // sub    sp, #0xc

    let mut emu = CpuARM::new(unicorn::Mode::THUMB).expect("failed to instantiate emulator");
    assert_eq!(emu.reg_write(unicorn::RegisterARM::R1, 123), Ok(()));
    assert_eq!(emu.reg_read(unicorn::RegisterARM::R1), Ok((123)));

    // Attempt to write to memory before mapping it.
    assert_eq!(emu.mem_write(0x1000, &arm_code32),
               (Err(unicorn::Error::WRITE_UNMAPPED)));

    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &arm_code32), Ok(()));
    assert_eq!(emu.mem_read(0x1000, arm_code32.len()),
               Ok(arm_code32.clone()));

    assert_eq!(emu.reg_write(unicorn::RegisterARM::SP, 12), Ok(()));
    assert_eq!(emu.reg_write(unicorn::RegisterARM::R0, 10), Ok(()));

    assert_eq!(emu.emu_start(0x1000,
                             (0x1000 + arm_code32.len()) as u64,
                             10 * unicorn::SECOND_SCALE,
                             1000),
               Ok(()));
    assert_eq!(emu.reg_read(unicorn::RegisterARM::SP), Ok((0)));
    assert_eq!(emu.reg_read(unicorn::RegisterARM::R0), Ok((10)));
}

#[test]
fn emulate_mips() {
    let mips_code32 = vec![0x56, 0x34, 0x21, 0x34]; // ori $at, $at, 0x3456;

    let mut emu = CpuMIPS::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &mips_code32), Ok(()));
    assert_eq!(emu.mem_read(0x1000, mips_code32.len()),
               Ok(mips_code32.clone()));
    assert_eq!(emu.reg_write(unicorn::RegisterMIPS::AT, 0), Ok(()));
    assert_eq!(emu.emu_start(0x1000,
                             (0x1000 + mips_code32.len()) as u64,
                             10 * unicorn::SECOND_SCALE,
                             1000),
               Ok(()));
    assert_eq!(emu.reg_read(unicorn::RegisterMIPS::AT), Ok((0x3456)));
}

#[test]
fn mem_unmapping() {
    let emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL), Ok(()));
    assert_eq!(emu.mem_unmap(0x1000, 0x4000), Ok(()));
}
