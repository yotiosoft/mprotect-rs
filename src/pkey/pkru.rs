use std::arch::asm;

#[inline]
pub unsafe fn rdpkru() -> u32 {
    let value: u32;
    asm!(
        "rdpkru",
        out("eax") value, out("edx") _, in("ecx") 0,
        options(nomem, nostack, preserves_flags)
    );
    value
}

#[inline]
pub unsafe fn wrpkru(pkru: u32) {
    asm!(
        "wrpkru",
        in("ecx") 0, in("edx") 0, in("eax") pkru,
        options(nostack, preserves_flags)
    );
}
