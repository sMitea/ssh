extern crate pkg_config;
#[cfg(target_env = "msvc")]
extern crate vcpkg;

use std::path::{Path, PathBuf};
use std::{env, process::Command};

fn check_update_git() {
    if !Path::new("libssh/.git").exists() {
        let _ = Command::new("git")
            .args(&["submodule", "update", "--init"])
            .status();
    }
}

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
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let mut cfg = cmake::Config::new("libssh");
    cfg.define("WITH_EXAMPLES", "OFF");
    cfg.define("UNIT_TESTING", "OFF");
    cfg.define("BUILD_STATIC_LIB", "ON");
    cfg.define("BUILD_SHARED_LIBS", "OFF");
    cfg.define("CMAKE_INSTALL_PREFIX", format!("{}", out_dir.display()));
    let dst = cfg.build();
    println!("cargo:rustc-link-search=native={}", dst.join("lib").display());
    println!("cargo:rustc-link-lib=static={}", "ssh");
}
