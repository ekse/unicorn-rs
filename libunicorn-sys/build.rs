extern crate build_helper;
extern crate gcc;
extern crate os_type;
extern crate pkg_config;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::env;
use std::ffi::{OsString, OsStr};

use build_helper::rustc::{link_search, link_lib};

fn get_vcvars_path() -> OsString {
    let vswhere_output = Command::new(r"build_tools\vswhere.exe")
        .args(&[
            "-latest",
            "-legacy",
            "-property",
            "installationPath"])
        .output()
        .expect("failed to execute vswhere.exe");

    if !vswhere_output.status.success() {
        fail("vswhere failed to locate Microsoft Visual Studio");
    }

    let visual_studio_path = {
        let vswhere_stdout = String::from_utf8(vswhere_output.stdout)
            .expect("vswhere output is not valid UTF-8");
        String::from(vswhere_stdout.trim())
    };

    match build_helper::target::triple().arch() {
        "i686" => {
            let old_style_path = [&visual_studio_path, "VC", "bin", "vcvars32.bat"].iter().collect::<PathBuf>();
            if old_style_path.is_file() {
                return old_style_path.into_os_string();
            }

            let new_style_path = [&visual_studio_path, "VC", "Auxiliary", "Build", "vcvars32.bat"].iter().collect::<PathBuf>();
            if new_style_path.is_file() {
                return new_style_path.into_os_string();
            }

            panic!("failed to locate 'vcvars32.bat'");
        },
        "x86_64" => {
            let old_style_path = [&visual_studio_path, "VC", "bin", "x86_amd64", "vcvarsx86_amd64.bat"].iter().collect::<PathBuf>();
            if old_style_path.is_file() {
                return old_style_path.into_os_string();
            }

            let new_style_path = [&visual_studio_path, "VC", "Auxiliary", "Build", "vcvarsx86_amd64.bat"].iter().collect::<PathBuf>();
            if new_style_path.is_file() {
                return new_style_path.into_os_string();
            }

            panic!("failed to locate 'vcvarsx86_amd64.bat'");
        },
        arch => panic!("'{}' is not a valid architecture for MSVC builds", arch)
    }
}

fn main() {
    if !build_helper::windows() {
        if Command::new("pkg-config").output().is_ok()
            && pkg_config::Config::new().atleast_version("1.0.0").probe("unicorn").is_ok() {
            return;
        }
    }

    if !Path::new("unicorn/.git").exists() {
        let _ = Command::new("git")
            .args(&["submodule", "update", "--init", "--depth", "5"])
            .status();
    }
    let out_dir = env::var("OUT_DIR").unwrap();

    let make_args = match os_type::current_platform() {
        os_type::OSType::OSX => ["macos-universal-no"],
        _ => [""],
    };

    if build_helper::target::triple().env().unwrap_or("").contains("msvc") {
        let build_cmd_path: PathBuf = [
            env::current_dir().expect("failed to retrieve current directory").as_path(),
            Path::new("build_tools"),
            Path::new("msvc_build.bat")].iter().collect();

        let platform_toolset = match env::var("PLATFORMTOOLSET") {
            Ok(x) => format!("PlatformToolset={};", x),
            Err(_) => "".to_owned(),
        };

        let status = match Command::new(build_cmd_path)
            .args(&[&get_vcvars_path(), OsStr::new(&out_dir), OsStr::new(&platform_toolset)])
            .current_dir("unicorn")
            .status() {
            Ok(status) => status,
            Err(e) => fail(&format!("failed to execute command: {}", e)),
        };
        if !status.success() {
            fail(&format!("command did not execute successfully, got {}", status));
        }

        link_search(Some(build_helper::SearchKind::Native), build_helper::out_dir());
        link_lib(Some(build_helper::LibKind::Static), "unicorn_static");
    } else {
        // TODO(sduquette): the package build should fail if this command fails.
        let _ = Command::new("./make.sh").args(&make_args).current_dir("unicorn").status();

        let unicorn = "libunicorn.a";
        let _ = Command::new("cp").current_dir("unicorn").arg(&unicorn).arg(&out_dir).status();
        
        link_search(Some(build_helper::SearchKind::Native), build_helper::out_dir());
        link_lib(Some(build_helper::LibKind::Static), "unicorn");
    }
}

fn fail(s: &str) -> ! {
    panic!("\n{}\n\nbuild script failed, must exit now", s)
}
