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
    check_update_git();
    let target = env::var("TARGET").unwrap();
    if try_vcpkg(){
        return;
    }

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
            if let Some(path) = path.to_str() {
                if path.len() > 0 {
                    cfg.define("OPENSSL_ROOT_DIR", path);
                }
            }
        }
    }

    cfg.define("WITH_EXAMPLES", "OFF");
    cfg.define("UNIT_TESTING", "OFF");
    cfg.define("BUILD_STATIC_LIB", "ON");
    cfg.define("BUILD_SHARED_LIBS", "OFF");
    cfg.define("CMAKE_INSTALL_PREFIX", format!("{}", out_dir.display()));
    let dst = cfg.build();
    println!("cargo:rustc-link-search=native={}", dst.join("lib").display());
    if target.contains("windows") {
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=crypt32");
        println!("cargo:rustc-link-lib=user32");
        println!("cargo:rustc-link-lib=ntdll");
    }
}


#[cfg(not(target_env = "msvc"))]
fn try_vcpkg() -> bool {
    false
}

#[cfg(target_env = "msvc")]
fn try_vcpkg() -> bool {
    vcpkg::Config::new()
        .emit_includes(true)
        .probe("libssh")
        .map(|_| {
            // found libssh which depends on openssl and zlib
            vcpkg::Config::new()
                .lib_name("libssl")
                .lib_name("libcrypto")
                .probe("openssl")
                .or_else(|_| {
                    // openssl 1.1 was not found, try openssl 1.0
                    vcpkg::Config::new()
                        .lib_name("libeay32")
                        .lib_name("ssleay32")
                        .probe("openssl")
                })
                .expect(
                    "configured libssh from vcpkg but could not \
                     find openssl libraries that it depends on",
                );

            vcpkg::Config::new()
                .lib_names("zlib", "zlib1")
                .probe("zlib")
                .expect(
                    "configured libssh from vcpkg but could not \
                     find the zlib library that it depends on",
                );

            println!("cargo:rustc-link-lib=crypt32");
            println!("cargo:rustc-link-lib=gdi32");
            println!("cargo:rustc-link-lib=user32");
        })
        .is_ok()
}