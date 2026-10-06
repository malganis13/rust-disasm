use disasm_core::{
    analysis::Analysis,
    loader::{Arch, Binary},
};

fn decompile_raw(code: &[u8]) -> String {
    let bin = Binary::raw(code, 0x1000, Arch::X86_64);
    let a = Analysis::run(&bin);
    let f = a.function(0x1000).expect("entry function");
    decompiler::decompile(f, bin.arch).expect("decompile")
}

#[test]
fn if_else() {
    // int f(int x){ if (x==0) return g(); return 1; }  (frame-pointer style)
    let code = [
        0x55, 0x48, 0x89, 0xe5, 0x83, 0xff, 0x00, 0x74, 0x07, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x5d, 0xc3, 0xe8,
        0x02, 0x00, 0x00, 0x00, 0x5d, 0xc3, 0x31, 0xc0, 0xc3,
    ];
    let c = decompile_raw(&code);
    println!("{c}");
    assert!(c.contains("if ("), "{c}");
    assert!(c.contains("sub_1017()"), "{c}");
    assert!(c.contains("return 1;") || c.contains("return 0x1;"), "{c}");
    assert!(c.contains("a1"), "parameter recovered: {c}");
}

#[test]
fn counting_loop() {
    // xor eax,eax ; L: cmp eax,edi ; jge done ; add eax,1 ; jmp L ; done: ret
    let code = [
        0x31, 0xc0, // xor eax,eax
        0x39, 0xf8, // cmp eax,edi
        0x7d, 0x05, // jge +5
        0x83, 0xc0, 0x01, // add eax,1
        0xeb, 0xf7, // jmp -9
        0xc3,
    ];
    let c = decompile_raw(&code);
    println!("{c}");
    assert!(c.contains("while ("), "{c}");
    assert!(!c.contains("goto"), "{c}");
}

#[test]
fn whole_self_binary_does_not_panic() {
    let exe = std::env::current_exe().unwrap();
    let bin = Binary::from_path(exe).unwrap();
    if bin.arch.bitness().is_none() {
        // Host is not x86 (e.g. Apple Silicon): the decompiler must refuse cleanly.
        let a = Analysis::run(&bin);
        if let Some(f) = a.functions().next() {
            assert!(decompiler::decompile(f, bin.arch).is_err());
        }
        return;
    }
    let a = Analysis::run(&bin);
    let mut ok = 0;
    for f in a.functions().take(300) {
        if decompiler::decompile(f, bin.arch).is_ok() {
            ok += 1;
        }
    }
    assert!(ok > 50, "decompiled {ok}");
}
