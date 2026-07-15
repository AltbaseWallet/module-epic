use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "windows" {
        println!("cargo:rustc-link-lib=dylib=winsqlite3");
    } else {
        println!("cargo:rustc-link-lib=dylib=sqlite3");
        return;
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo did not set OUT_DIR"));
    let resource_script = out_dir.join("altbase_epic_transport.rc");
    let resource_object = out_dir.join("altbase_epic_transport.res");
    let resource_text = r#"
1 VERSIONINFO
 FILEVERSION 0,1,5,0
 PRODUCTVERSION 0,1,5,0
 FILEFLAGSMASK 0x3fL
 FILEFLAGS 0x0L
 FILEOS 0x40004L
 FILETYPE 0x2L
 FILESUBTYPE 0x0L
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "Altbase"
      VALUE "FileDescription", "Altbase Epic Transport"
      VALUE "FileVersion", "0.1.5"
      VALUE "InternalName", "AltbaseEpicTransport"
      VALUE "LegalCopyright", "Copyright (C) Altbase"
      VALUE "OriginalFilename", "altbase_epic_transport.dll"
      VALUE "ProductName", "Altbase Wallet"
      VALUE "ProductVersion", "0.1.5"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#;
    fs::write(&resource_script, resource_text).expect("failed to write Epic transport resource");
    let status = Command::new("rc.exe")
        .arg("/nologo")
        .arg(format!("/fo{}", resource_object.display()))
        .arg(&resource_script)
        .status()
        .expect("failed to start the Windows resource compiler");
    assert!(status.success(), "Windows resource compilation failed");
    println!("cargo:rustc-link-arg={}", resource_object.display());
    for option in [
        "/DYNAMICBASE", "/NXCOMPAT", "/HIGHENTROPYVA", "/CETCOMPAT",
        "/OPT:REF", "/OPT:ICF", "/INCREMENTAL:NO", "/RELEASE", "/Brepro",
    ] {
        println!("cargo:rustc-link-arg={option}");
    }
}
