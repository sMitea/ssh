extern crate pkg_config;
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
    check_update_git();
    println!("cargo:rerun-if-env-changed=LIBSSH_SYS_USE_PKG_CONFIG");
    if env::var("LIBSSH_SYS_USE_PKG_CONFIG").is_ok() {
        if let Ok(lib) = pkg_config::find_library("libssh") {
            for path in &lib.include_paths {
                println!("cargo:include={}", path.display());
            }
            return;
        }
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let mut cfg = cmake::Config::new("libssh");
    println!("cargo:rerun-if-env-changed=DEP_OPENSSL_INCLUDE");
    if let Some(path) = env::var_os("DEP_OPENSSL_INCLUDE") {
        if let Some(path) = env::split_paths(&path).next() {
            if let Some(path) = path.parent() {
                if let Some(path) = path.to_str() {
                    if path.len() > 0 {
                        cfg.define("OPENSSL_ROOT_DIR", path);
                    }
                }
            }
        }
    }

    cfg.define("WITH_EXAMPLES", "OFF");
    cfg.define("UNIT_TESTING", "OFF");
    cfg.define("CMAKE_INSTALL_PREFIX", format!("{}", out_dir.display()));
    let dst = cfg.build();
    println!(
        "cargo:rustc-link-search=native={}",
        dst.join("lib").display()
    );
}
