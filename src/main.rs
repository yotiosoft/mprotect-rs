use mprotect_rs::*;

fn main() -> Result<(), MprotectError> {
    let pkey = ProtectionKey::new(PkeyAccessRights::EnableAccessWrite)?;
    let mut protected_mem = ProtectedMemory::<u32>::with_pkey_mprotect(AccessRights::ReadWrite, &pkey)?;

    //let mut protected_mem = ProtectedMemory::<u32>::with_mprotect(AccessRights::Read)?;

    // Write to the protected memory
    println!("Set the value to 42");
    *protected_mem.as_mut() = 42;
    println!("Value written: {}", *protected_mem.as_ref());

    // Set the pkey to read-only
    //protected_mem.pkey_mprotect(AccessRights::Read)?;
    println!("Set pkey {} to read-only", pkey.key());
    pkey.set_access_rights(PkeyAccessRights::DisableWrite)?;

    // Read from the protected memory
    println!("Value read: {}", *protected_mem.as_ref());

    // Create another pkey and allocate another memory region with it
    println!("Create another pkey and allocate another memory region with it");
    let pkey2 = ProtectionKey::new(PkeyAccessRights::EnableAccessWrite)?;
    println!("Created another pkey {}", pkey2.key());
    pkey2.set_access_rights(PkeyAccessRights::EnableAccessWrite)?;
    let mut new_memory = ProtectedMemory::<u32>::with_pkey_mprotect(AccessRights::ReadWrite, &pkey2)?;
    *new_memory.as_mut() = 100;
    println!("Value in new memory: {}", *new_memory.as_ref());

    // Set the pkey 1 to no access
    //protected_mem.pkey_mprotect(AccessRights::None)?;
    println!("Set pkey {} to no access", pkey.key());
    pkey.set_access_rights(PkeyAccessRights::DisableAccess)?;

    // This will likely cause a segmentation fault
    println!("Value read: {}", *protected_mem.as_ref());

    Ok(())
}
