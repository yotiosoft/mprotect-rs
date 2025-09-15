use mprotect_rs::*;

fn main() -> Result<(), MprotectError> {
    let pkey = ProtectionKey::new(PkeyAccessRights::EnableAccessWrite)?;
    let mut protected_mem = ProtectedMemory::<allocator::Mmap, u32>::with_pkey(AccessRights::ReadWrite, &pkey)?;

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
    let mut new_memory = ProtectedMemory::<allocator::Jmalloc, u32>::with_pkey(AccessRights::ReadWrite, &pkey2)?;
    println!("Set the value in pkey {} memory to 100", pkey2.key());
    *new_memory.as_mut() = 100;
    println!("\tValue in new memory: {}", *new_memory.as_ref());
    println!("\tWriting to new memory succeeded");

    // Create another pkey and switch the pkey of the existing memory region to it
    println!("Attempt to create another pkey and switch the existing memory to it");
    let pkey3 = ProtectionKey::new(PkeyAccessRights::DisableWrite)?;
    println!("\tCreated another pkey {}", pkey3.key());
    protected_mem.pkey_mprotect(AccessRights::Read, &pkey3)?;
    println!("Switched the existing memory (before: pkey {}, now: pkey {})", pkey.key(), pkey3.key());

    // Read from the memory region (should succeed)
    println!("Attempt to read the value");
    println!("\tValue read: {}", *protected_mem.as_ref());
    println!("\tReading succeeded");

    // Write to the memory region (should fail)
    println!("Attempt to write the value 84 (this will likely cause a segmentation fault!");
    *protected_mem.as_mut() = 84;
    println!("\tValue written: {}", *protected_mem.as_ref());
    println!("\tWriting succeeded (this is unexpected!)");

    // Set the pkey 1 to no access
    //protected_mem.pkey_mprotect(AccessRights::None)?;
    println!("Set pkey {} to no access", pkey.key());
    pkey.set_access_rights(PkeyAccessRights::DisableAccess)?;

    // This will likely cause a segmentation fault
    println!("Attempt to read the value again (this will likely cause a segmentation fault!)");
    println!("\tValue read: {}", *protected_mem.as_ref());
    panic!("This line should not be reached!");
}
