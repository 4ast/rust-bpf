use std::process::Command;

fn cfg(args: &[&str]) -> String {
    let bin = std::env::var("LLVM_CONFIG").unwrap_or_else(|_| "llvm-config".into());
    let out = Command::new(&bin).args(args).output().expect("llvm-config");
    assert!(out.status.success(), "{bin} {args:?} failed");
    String::from_utf8(out.stdout).unwrap()
}

fn main() {
    println!("cargo:rerun-if-env-changed=LLVM_CONFIG");
    println!("cargo:rustc-link-search=native={}", cfg(&["--libdir"]).trim());
    let comps = ["core", "bitreader", "bitwriter"];
    let mut a = vec!["--link-static", "--libs"];
    a.extend(comps);
    for l in cfg(&a).split_whitespace() {
        println!("cargo:rustc-link-lib=static={}", l.trim_start_matches("-l"));
    }
    // With the components: llvm-config insists on the libraries of what it is
    // asked about, and a build tree need not have all of LLVM.
    let mut a = vec!["--link-static", "--system-libs"];
    a.extend(comps);
    for l in cfg(&a).split_whitespace() {
        if let Some(l) = l.strip_prefix("-l") {
            println!("cargo:rustc-link-lib=dylib={l}");
        }
    }
    println!("cargo:rustc-link-lib=dylib=stdc++");
}
