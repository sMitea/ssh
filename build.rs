extern crate pkg_config;
#[cfg(target_env = "msvc")]
extern crate vcpkg;

use std::path::Path;
use std::{env, process::Command};

fn check_update_git() {
    if !Path::new("libssh/.git").exists() {
        let _ = Command::new("git")
            .args(&["submodule", "update", "--init"])
            .status();
    }
}

#[cfg(target_os = "macos")]
const INSTALL_PATH : &str = "/usr/local";

#[cfg(target_os = "linux")]
const INSTALL_PATH : &str = "/usr/local";

fn main() {
    println!("cargo:rerun-if-env-changed=LIBSSH_SYS_USE_PKG_CONFIG");
    if env::var("LIBSSH_SYS_USE_PKG_CONFIG").is_ok() {
        if let Ok(lib) = pkg_config::find_library("libssh") {
            for path in &lib.include_paths {
                println!("cargo:include={}", path.display());
            }
            return;
        }
    }

    check_update_git();
    let mut cfg = cmake::Config::new("libssh");
    cfg.define("WITH_EXAMPLES", "OFF");
    cfg.define("UNIT_TESTING", "OFF");
    cfg.define("BUILD_STATIC_LIB", "ON");
    cfg.define("BUILD_SHARED_LIBS", "OFF");
    cfg.define("CMAKE_INSTALL_PREFIX", INSTALL_PATH);
    let _ = cfg.build();
}
