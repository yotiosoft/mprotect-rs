use mprotect_rs::*;

fn main() -> Result<(), MprotectError> {
    let pkey = ProtectionKey::new(PkeyAccessRights::EnableAccessWrite)?;
    let mut protected_mem = ProtectedMemory::<u32>::with_pkey(AccessRights::ReadWrite, &pkey)?;

    //let mut protected_mem = ProtectedMemory::<u32>::without_pkey(AccessRights::Read)?;

    // Write to the protected memory
    println!("Attempt to write the value 42");
    *protected_mem.as_mut() = 42;
    println!("\tValue written: {}", *protected_mem.as_ref());
    println!("\tWriting succeeded");

    // Set the pkey to read-only
    //protected_mem.pkey_mprotect(AccessRights::Read)?;
    println!("Set pkey {} to read-only", pkey.key());
    pkey.set_access_rights(PkeyAccessRights::DisableWrite)?;

    // Read from the protected memory
    println!("Attempt to read the value");
    println!("\tValue read: {}", *protected_mem.as_ref());
    println!("\tReading succeeded");

    // Create another pkey and allocate another memory region with it
    println!("Attempt to create another pkey and allocate memory with it");
    let pkey2 = ProtectionKey::new(PkeyAccessRights::EnableAccessWrite)?;
    println!("\tCreated another pkey {}", pkey2.key());
    let mut new_memory = ProtectedMemory::<u32>::with_pkey(AccessRights::ReadWrite, &pkey2)?;
    println!("Set the value in pkey {} memory to 100", pkey2.key());
    *new_memory.as_mut() = 100;
    println!("\tValue in new memory: {}", *new_memory.as_ref());
    println!("\tWriting to new memory succeeded");

    // Set the pkey 1 to no access
    //protected_mem.pkey_mprotect(AccessRights::None)?;
    println!("Set pkey {} to no access", pkey.key());
    pkey.set_access_rights(PkeyAccessRights::DisableAccess)?;

    // This will likely cause a segmentation fault
    println!("Attempt to read the value again (this will likely cause a segmentation fault!)");
    println!("\tValue read: {}", *protected_mem.as_ref());
    panic!("This line should not be reached!");
}
