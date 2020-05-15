extern crate pkg_config;

#[cfg(target_env = "msvc")]
extern crate vcpkg;

fn main() {
    if try_vcpkg() {
        return;
    }

    pkg_config::Config::new()
        .atleast_version("0.8")
        .statik(false)
        .probe("libssh")
        .expect("dynamically linked libssh >= 0.8 is required");
}

#[cfg(not(target_env = "msvc"))]
fn try_vcpkg() -> bool {
    false
}

#[cfg(target_env = "msvc")]
fn try_vcpkg() -> bool {
    vcpkg::Config::new()
        .atleast_version("0.7")
        .statik(false)
        .probe("libssh")
        .expect("dynamically linked libssh >= 0.7 is required");
}
