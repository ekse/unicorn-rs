# unicorn-rs

[![Cargo](https://img.shields.io/crates/v/unicorn.svg)](https://crates.io/crates/unicorn)
[![Documentation](https://docs.rs/unicorn/badge.svg)](https://docs.rs/unicorn)
[Build Status]: https://api.travis-ci.org/serde-rs/serde.svg?branch=master
[travis]: https://travis-ci.org/serde-rs/serde

**Looking for maintainers**: I am looking for new maintainers for the project. If you are interested, please open an issue or contact me by email at ekse.0x@gmail.com.

Rust bindings for the [unicorn](http://www.unicorn-engine.org/) CPU emulator.

```rust
extern crate unicorn;

use unicorn::{Cpu, CpuX86};

fn main() {
    let x86_code32: Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx

    let emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    let _ = emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL);
    let _ = emu.mem_write(0x1000, &x86_code32);
    let _ = emu.reg_write_i32(unicorn::RegisterX86::ECX, -10);
    let _ = emu.reg_write_i32(unicorn::RegisterX86::EDX, -50);

    let _ = emu.emu_start(0x1000, (0x1000 + x86_code32.len()) as u64, 10 * unicorn::SECOND_SCALE, 1000);
    assert_eq!(emu.reg_read_i32(unicorn::RegisterX86::ECX), Ok((-9)));
    assert_eq!(emu.reg_read_i32(unicorn::RegisterX86::EDX), Ok((-51)));
}
```

## Installation

This project has been tested on Linux, OS X and Windows. The bindings are built for version 1.0 of
unicorn.

This package attempts to build unicorn if it is not already installed on the system. To build
unicorn on Linux and OS X, the following tools are needed : gcc, make, git, python 2.7. Visual
Studio is needed on Windows.

To use unicorn-rs, simply add it as dependency to the Cargo.toml of your program.

```
[dependencies]
unicorn = "0.8.0"
```

## Changelog

### 0.8.0

Added support for `mem_map_ptr`.

### 0.7.0

Windows is now supported (thanks to kichristensen).

### 0.6.0

We now check if unicorn is installed on the system via pkg-tool and use that version if available.
Otherwise unicorn is compiled when building the package.

### 0.4.0

unicorn is now compiled as part of the build process of unicorn-rs.

### 0.3.0

The handling of callbacks has been modified, callbacks should be implemented using closures. See
the tests for examples.

- added support for interrupt, in/out and sysenter callbacks


## Contributing

Contributions to this project are super appreciated. Pull requests, bug reports, code review, tests,
documentation or feedback on your use of the bindings, nothing is too small. Don't hesitate to open
an issue if you have questions.

Contributors:

- Sébastien Duquette (@ekse)
- Israel Hallé (@isra17) for redesigning the callbacks API
- Richo Healey (@richo)
- Kim Christensen (@kichristensen) for the Windows support
- petevine for reviewing the project and adding tests
- jschievink for his help with the API design
- m4b for the build.rs script
