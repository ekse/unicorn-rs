extern crate gcc;

use std::path::{Path};
use std::process::Command;
use std::env;

fn main() {
    if !Path::new("unicorn/.git").exists() {
        let _ = Command::new("git").args(&["submodule", "update", "--init", "--depth", "5"])
            .status();
    }
    let out_dir = env::var("OUT_DIR").unwrap();
    let _ = Command::new("./make.sh").current_dir("unicorn").status();
    let unicorn = "libunicorn.a";
    let _ = Command::new("cp").current_dir("unicorn").arg(&unicorn).arg(&out_dir).status();
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=unicorn");
}
