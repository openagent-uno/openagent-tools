fn main() {
    println!("cargo:rerun-if-changed=src/native_advanced.m");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") { return; }
    // Resolve compiler and archiver through the same selected Apple toolchain.
    // PATH may contain GNU binutils, whose archive index is not a Mach-O member.
    const XCRUN: &str = "/usr/bin/xcrun";
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() { "aarch64" => "arm64", "x86_64" => "x86_64", _ => panic!("unsupported macOS architecture") };
    let sdk = std::process::Command::new(XCRUN).args(["--sdk", "macosx", "--show-sdk-path"]).output().expect("macOS SDK required to compile native controls");
    assert!(sdk.status.success(), "macOS SDK lookup failed");
    let sdk = String::from_utf8(sdk.stdout).unwrap();
    let deployment = std::env::var("MACOSX_DEPLOYMENT_TARGET").unwrap_or_else(|_| "12.0".into());
    let parts: Vec<u32> = deployment.split('.').map(|part| part.parse().expect("numeric macOS deployment target required")).collect();
    assert!(!parts.is_empty() && parts.len() <= 3 && parts[0] >= 12, "native controls require MACOSX_DEPLOYMENT_TARGET >= 12.0");
    let minimum = format!("-mmacosx-version-min={deployment}");
    let object = output.join("native_advanced.o");
    let status = std::process::Command::new(XCRUN).args(["--sdk", "macosx", "clang", "-arch", arch, "-isysroot", sdk.trim(), &minimum, "-fobjc-arc", "-fblocks", "-O2", "-Werror=implicit-function-declaration", "-Wno-deprecated-declarations", "-c", "src/native_advanced.m", "-o"]).arg(&object).status().expect("native Objective-C compiler required");
    assert!(status.success(), "native controls compilation failed");
    let archive = output.join("libopenagent_native_advanced.a");
    // Recreate only our generated OUT_DIR archive: updating an older GNU archive
    // can retain its incompatible '/' index even after switching archivers.
    match std::fs::remove_file(&archive) {
        Ok(()) => {},
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => panic!("cannot replace native controls build archive: {error}"),
    }
    let status = std::process::Command::new(XCRUN)
        .args(["--sdk", "macosx", "ar", "crs"])
        .arg(&archive)
        .arg(object)
        .status()
        .expect("Apple archiver required to compile native controls");
    assert!(status.success(), "native controls archive failed");
    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-lib=static=openagent_native_advanced");
    // Rust's release linker uses -nodefaultlibs. Explicitly retain compiler-rt's
    // availability implementation used by Objective-C @available checks.
    let runtime = std::process::Command::new(XCRUN)
        .args(["--sdk", "macosx", "clang", "--print-file-name=libclang_rt.osx.a"])
        .output()
        .expect("selected Apple clang must provide its availability runtime");
    assert!(runtime.status.success(), "Apple compiler runtime lookup failed");
    let runtime = std::path::PathBuf::from(String::from_utf8(runtime.stdout).unwrap().trim());
    assert!(runtime.is_absolute() && runtime.is_file(), "selected Apple compiler runtime is unavailable: {}", runtime.display());
    println!("cargo:rustc-link-search=native={}", runtime.parent().unwrap().display());
    println!("cargo:rustc-link-lib=static=clang_rt.osx");
    for name in ["Foundation", "AppKit", "AVFoundation", "AVFAudio", "CoreMedia", "AudioToolbox", "CoreGraphics"] { println!("cargo:rustc-link-lib=framework={name}"); }
    println!("cargo:rustc-link-arg=-Wl,-weak_framework,ScreenCaptureKit");
}
