extern crate cc;
extern crate pkg_config;

#[cfg(target_env = "msvc")]
extern crate vcpkg;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let mut cfg = cc::Build::new();
    // project path
    let target = env::var("TARGET").unwrap();
    let dst = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let build = dst.join("build");
    let include = dst.join("include");
    let libssh_include = include.join("libssh");
    println!("cargo:include={}", include.display());
    println!("cargo:root={}", dst.display());

    // project info
    let mut project = fs::read_to_string("libssh/CMakeLists.txt").unwrap();
    project = project
        .lines()
        .filter(|v| v.contains("project("))
        .last()
        .map(|v| v.replace("project(", "").replace(")", ""))
        .unwrap();
    let mut project = project.split_whitespace();
    let lib_name = project.next().unwrap();
    let _ = project.next().unwrap();
    let lib_version = project.next().unwrap();
    let lib_path = dst.join("lib");
    let src_path: PathBuf = "libssh/src".parse().unwrap();
    println!("lib name: {}, version: {}", lib_name, lib_version);

    let mut config = String::new();
    config.push_str(&format!("#define PACKAGE \"{}\"\n", lib_name));
    config.push_str(&format!("#define VERSION \"{}\"\n", lib_version));
    config.push_str(&format!(
        "#define BINARYDIR \"{}\"",
        &lib_path.to_str().unwrap()
    ));
    config.push_str(&format!(
        "#define SOURCEDIR \"{}\"\n",
        &src_path.to_str().unwrap()
    ));
    config.push_str(&format!(
        "#define GLOBAL_BIND_CONFIG \"{}\"\n",
        "/etc/ssh/libssh_server_config"
    ));
    config.push_str(&format!(
        "#define GLOBAL_CLIENT_CONFIG \"{}\"\n",
        "/etc/ssh/ssh_config"
    ));

    // find package
    println!("cargo:rerun-if-env-changed=LIBSSH_SYS_USE_PKG_CONFIG");
    if env::var("LIBSSH_SYS_USE_PKG_CONFIG").is_ok() {
        if let Ok(lib) = pkg_config::find_library("libssh") {
            for path in &lib.include_paths {
                println!("cargo:include={}", path.display());
            }
            return;
        }
    }

    // update resp
    if !Path::new("libssh/.git").exists() {
        let _ = Command::new("git")
            .args(&["submodule", "update", "--init"])
            .status();
    }

    cfg.out_dir(&build);
    fs::create_dir_all(&build).unwrap();
    fs::create_dir_all(&include).unwrap();
    fs::create_dir_all(&libssh_include).unwrap();

    // make libssh_version.h
    fs::write(
        libssh_include.join("libssh_version.h"),
        fs::read_to_string("libssh/include/libssh/libssh_version.h.cmake")
            .unwrap()
            .replace("@libssh_VERSION_MAJOR@", "0")
            .replace("@libssh_VERSION_MINOR@", "8")
            .replace("@libssh_VERSION_PATCH@", "90"),
    )
    .unwrap();

    // copy include files
    fs::copy(
        "libssh/include/libssh/callbacks.h",
        libssh_include.join("callbacks.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/libssh.h",
        libssh_include.join("libssh.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/ssh2.h",
        libssh_include.join("ssh2.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/legacy.h",
        libssh_include.join("legacy.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/sftp.h",
        libssh_include.join("sftp.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/agent.h",
        libssh_include.join("agent.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/priv.h",
        libssh_include.join("priv.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/socket.h",
        libssh_include.join("socket.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/buffer.h",
        libssh_include.join("buffer.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/session.h",
        libssh_include.join("session.h"),
    )
    .unwrap();
    fs::copy("libssh/include/libssh/kex.h", libssh_include.join("kex.h")).unwrap();
    fs::copy(
        "libssh/include/libssh/packet.h",
        libssh_include.join("packet.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/wrapper.h",
        libssh_include.join("wrapper.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/libcrypto.h",
        libssh_include.join("libcrypto.h"),
    ).unwrap();
    fs::copy(
        "libssh/include/libssh/crypto.h",
        libssh_include.join("crypto.h")
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/libmbedcrypto.h",
        libssh_include.join("libmbedcrypto.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/libgcrypt.h",
        libssh_include.join("libgcrypt.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/pcap.h",
        libssh_include.join("pcap.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/auth.h",
        libssh_include.join("auth.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/channels.h",
        libssh_include.join("channels.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/poll.h",
        libssh_include.join("poll.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/config.h",
        libssh_include.join("config.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/misc.h",
        libssh_include.join("misc.h"),
    )
    .unwrap();
    fs::copy("libssh/include/libssh/pki.h", libssh_include.join("pki.h")).unwrap();
    fs::copy(
        "libssh/include/libssh/crypto.h",
        libssh_include.join("crypto.h"),
    )
    .unwrap();
    fs::copy("libssh/include/libssh/dh.h", libssh_include.join("dh.h")).unwrap();
    fs::copy(
        "libssh/include/libssh/ecdh.h",
        libssh_include.join("ecdh.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/curve25519.h",
        libssh_include.join("curve25519.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/ed25519.h",
        libssh_include.join("ed25519.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/bytearray.h",
        libssh_include.join("bytearray.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/keys.h",
        libssh_include.join("keys.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/gssapi.h",
        libssh_include.join("gssapi.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/bignum.h",
        libssh_include.join("bignum.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/string.h",
        libssh_include.join("string.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/messages.h",
        libssh_include.join("messages.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/options.h",
        libssh_include.join("options.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/threads.h",
        libssh_include.join("threads.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/config_parser.h",
        libssh_include.join("config_parser.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/knownhosts.h",
        libssh_include.join("knownhosts.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/token.h",
        libssh_include.join("token.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/pki_priv.h",
        libssh_include.join("pki_priv.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/scp.h",
        libssh_include.join("scp.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/poly1305.h",
        libssh_include.join("poly1305.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/chacha20-poly1305-common.h",
        libssh_include.join("chacha20-poly1305-common.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/blf.h",
        libssh_include.join("blf.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/sftp_priv.h",
        libssh_include.join("sftp_priv.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/dh-gex.h",
        libssh_include.join("dh-gex.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/bind.h",
        libssh_include.join("bind.h"),
    )
    .unwrap();
    fs::copy(
        "libssh/include/libssh/bind_config.h",
        libssh_include.join("bind_config.h"),
    )
    .unwrap();

    // include src
    cfg.file("libssh/src/agent.c")
        .file("libssh/src/auth.c")
        .file("libssh/src/base64.c")
        .file("libssh/src/bignum.c")
        .file("libssh/src/buffer.c")
        .file("libssh/src/callbacks.c")
        .file("libssh/src/channels.c")
        .file("libssh/src/client.c")
        .file("libssh/src/config.c")
        .file("libssh/src/connect.c")
        .file("libssh/src/connector.c")
        .file("libssh/src/curve25519.c")
        .file("libssh/src/dh.c")
        .file("libssh/src/ecdh.c")
        .file("libssh/src/error.c")
        .file("libssh/src/getpass.c")
        .file("libssh/src/init.c")
        .file("libssh/src/kdf.c")
        .file("libssh/src/kex.c")
        .file("libssh/src/known_hosts.c")
        .file("libssh/src/knownhosts.c")
        .file("libssh/src/legacy.c")
        .file("libssh/src/log.c")
        .file("libssh/src/match.c")
        .file("libssh/src/messages.c")
        .file("libssh/src/misc.c")
        .file("libssh/src/options.c")
        .file("libssh/src/packet.c")
        .file("libssh/src/packet_cb.c")
        .file("libssh/src/packet_crypt.c")
        .file("libssh/src/pcap.c")
        .file("libssh/src/pki.c")
        .file("libssh/src/pki_container_openssh.c")
        .file("libssh/src/poll.c")
        .file("libssh/src/session.c")
        .file("libssh/src/scp.c")
        .file("libssh/src/socket.c")
        .file("libssh/src/string.c")
        .file("libssh/src/threads.c")
        .file("libssh/src/wrapper.c")
        .file("libssh/src/external/bcrypt_pbkdf.c")
        .file("libssh/src/external/blowfish.c")
        .file("libssh/src/config_parser.c")
        .file("libssh/src/token.c")
        .file("libssh/src/pki_ed25519_common.c")
        .file("libssh/src/sftp.c")
        .include(&include)
        .include("libssh/src");

    // include threads
    if env::var("CMAKE_USE_PTHREADS_INIT").is_ok() {
        cfg.file("libssh/src/threads/noop.c")
            .file("libssh/src/threads/pthread.c");
    } else if env::var("CMAKE_USE_WIN32_THREADS_INIT").is_ok() {
        cfg.file("libssh/src/threads/noop.c")
            .file("libssh/src/threads/winlocks.c");
    } else {
        cfg.file("libssh/src/threads/noop.c");
    }

    if target.contains("linux") {
        cfg.define("_MSC_VER", None);
    }

    // make libssh pkg
    let pkgconfig = dst.join("lib/pkgconfig");
    fs::create_dir_all(&pkgconfig).unwrap();
    fs::write(
        pkgconfig.join("libssh.pc"),
        fs::read_to_string("libssh/libssh.pc.cmake")
            .unwrap()
            .replace("${PROJECT_NAME}", "libssh")
            .replace(
                "${CMAKE_INSTALL_FULL_LIBDIR}",
                dst.join("lib").to_str().unwrap(),
            )
            .replace(
                "${CMAKE_INSTALL_FULL_INCLUDEDIR}",
                include.to_str().unwrap(),
            ),
    )
    .unwrap();

    // include openssl
    println!("cargo:rerun-if-env-changed=DEP_OPENSSL_INCLUDE");
    if let Some(path) = env::var_os("DEP_OPENSSL_INCLUDE") {
        if let Some(path) = env::split_paths(&path).next() {
            if let Some(path) = path.to_str() {
                if path.len() > 0 {
                    println!("cargo:include={}", path);
                    cfg.include(path);
                }
            }
        }
    } else if let Ok(lib) = pkg_config::find_library("openssl") {
        for path in &lib.include_paths {
            println!("cargo:include={}", path.display());
        }
    } else {
        return;
    }

    // define
    cfg.define("HAVE_OPENSSL_DES_H", None);
    cfg.define("HAVE_OPENSSL_AES_H", None);
    cfg.define("HAVE_OPENSSL_BLOWFISH_H", None);
    cfg.define("HAVE_OPENSSL_ECDH_H", None);
    cfg.define("HAVE_OPENSSL_EC_H", None);
    cfg.define("HAVE_OPENSSL_ECDSA_H", None);
    cfg.define("HAVE_OPENSSL_EVP_AES_CTR", None);
    cfg.define("HAVE_OPENSSL_EVP_AES_CBC", None);
    cfg.define("HAVE_OPENSSL_EVP_AES_GCM", None);
    cfg.define("HAVE_OPENSSL_CRYPTO_THREADID_SET_CALLBACK", None);
    cfg.define("HAVE_OPENSSL_CRYPTO_CTR128_ENCRYPT", None);
    cfg.define("HAVE_OPENSSL_EVP_CIPHER_CTX_NEW", None);
    cfg.define("HAVE_OPENSSL_EVP_KDF_CTX_NEW_ID", None);
    cfg.define("HAVE_OPENSSL_FIPS_MODE", None);
    cfg.define("HAVE_OPENSSL_RAND_PRIV_BYTES", None);
    cfg.define("HAVE_OPENSSL_EVP_DIGESTSIGN", None);
    cfg.define("HAVE_OPENSSL_EVP_DIGESTVERIFY", None);
    cfg.define("HAVE_OPENSSL_IA32CAP_LOC", None);
    cfg.define("HAVE_OPENSSL_ED25519", None);
    cfg.define("HAVE_OPENSSL_ECC", None);
    cfg.define("HAVE_ECC", None);
    cfg.define("HAVE_DSA", None);

    cfg.define("HAVE_LIBCRYPTO", None);
    cfg.define("HAVE_ISBLANK", None);
    cfg.define("HAVE_STRNCPY", None);
    cfg.define("HAVE_STRNDUP", None);
    cfg.define("HAVE_STRTOULL", None);
    cfg.define("HAVE_NTOHLL", None);
    cfg.define("HAVE_HTONLL", None);
    cfg.define("HAVE_GETADDRINFO", None);
    cfg.define("HAVE_COMPILER__FUNC__", None);
    cfg.define("HAVE_PTY_H", None);
    cfg.define("HAVE_TERMIOS_H", None);
    cfg.define("HAVE_UNISTD_H", None);
    cfg.define("HAVE_OPENSSL_ECDH_H", None);
    cfg.define("WITH_SYMBOL_VERSIONING", None);
    cfg.define("WITH_EXAMPLES", None);
    cfg.define("WITH_DEBUG_CALLTRACE", None);
    cfg.define("WITH_SFTP", None);
    cfg.define("HAVE_CLOCK_GETTIME", None);
    cfg.define("HAVE_SYS_TIME_H", None);
    cfg.define("WITH_GEX", None);

    fs::write(include.join("config.h"), config).unwrap();

    cfg.warnings(false).compile("ssh");

    if target.contains("windows") {
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=crypt32");
        println!("cargo:rustc-link-lib=user32");
        println!("cargo:rustc-link-lib=ntdll");
    }
}

#[cfg(target_env = "msvc")]
fn try_vcpkg() -> bool {
    vcpkg::Config::new()
        .emit_includes(true)
        .probe("libssh2")
        .map(|_| {
            // found libssh2 which depends on openssl and zlib
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
                    "configured libssh2 from vcpkg but could not \
                     find openssl libraries that it depends on",
                );

            vcpkg::Config::new()
                .lib_names("zlib", "zlib1")
                .probe("zlib")
                .expect(
                    "configured libssh2 from vcpkg but could not \
                     find the zlib library that it depends on",
                );

            println!("cargo:rustc-link-lib=crypt32");
            println!("cargo:rustc-link-lib=gdi32");
            println!("cargo:rustc-link-lib=user32");
        })
        .is_ok()
}
