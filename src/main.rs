use mprotect_rs::*;

fn main() -> Result<(), MprotectError> {
    let pkey = ProtectionKey::new(PkeyAccessRights::EnableAccessWrite)?;
    let protected_mem = ProtectedMemory::<u32>::with_pkey_mprotect(AccessRights::ReadWrite, pkey)?;

    unsafe {
        let ptr = protected_mem.ptr();
        *ptr = 42;
        println!("Value: {}", *ptr);
    }
    Ok(())
}
