use std::arch::asm;

/// Reads the current value of the PKRU register.
///
/// Executes the `RDPKRU` instruction to obtain the current protection key rights
/// for user pages (Intel MPK).
///
/// # Safety
///
/// This function is **unsafe** because it directly accesses a CPU register.
/// The caller must ensure that the CPU supports the PKU feature.
///
/// # Returns
///
/// The current 32-bit PKRU value.
///
/// # Example
///
/// ```
/// unsafe {
///     let pkru = rdpkru();
///     println!("PKRU = 0x{:08x}", pkru);
/// }
/// ```
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

/// Writes a value to the PKRU register.
///
/// Executes the `WRPKRU` instruction to update access rights
/// for memory pages managed by Intel MPK.
///
/// # Safety
///
/// This function is **unsafe** because it changes memory access rights
/// process-wide. Incorrect values may cause access violations.
///
/// # Arguments
///
/// * `pkru` — The new 32-bit PKRU value.
///
/// # Example
///
/// ```
/// unsafe {
///     let old = rdpkru();
///     wrpkru(old | 0b10); // Disable write for key 0
/// }
/// ```
#[inline]
pub unsafe fn wrpkru(pkru: u32) {
    asm!(
        "wrpkru",
        in("ecx") 0, in("edx") 0, in("eax") pkru,
        options(nostack, preserves_flags)
    );
}
