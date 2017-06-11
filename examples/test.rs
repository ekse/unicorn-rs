extern crate unicorn;

use unicorn::cpu_arm;

fn main() {
    let (major, minor) = unicorn::unicorn_version();
    println!("version : {}.{}", major, minor);
    println!("Support for:\n\t x86: {}\n\t arm: {}\n\t mips: {}",
             unicorn::arch_supported(unicorn::Arch::X86),
             unicorn::arch_supported(unicorn::Arch::ARM),
             unicorn::arch_supported(unicorn::Arch::MIPS));

    let emu = cpu_arm(unicorn::Mode::THUMB).expect("failed to create emulator");

    let page_size = emu.query(unicorn::Query::PAGE_SIZE).expect("failed to query page size");
    println!("page size : {}", page_size);
    let hardware_mode = emu.query(unicorn::Query::MODE).expect("failed to query hardware mode");
    println!("hardware mode : {}", hardware_mode);

    println!("Sample error message : {}", unicorn::Error::HOOK.msg());

    emu.mem_map(0x10000, 0x4000, unicorn::PROT_ALL).expect("failed to map first memory region");
    emu.mem_map(0x20000, 0x4000, unicorn::PROT_ALL).expect("failed to map second memory region");
    let regions = emu.mem_regions().expect("failed to retrieve memory mappings");
    println!("Regions : {}", regions.len());

    for region in &regions {
        println!("{:?}", region);
    }
}
