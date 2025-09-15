use mprotect_rs::*;

use std::process::Command;
use std::os::unix::process::ExitStatusExt;

fn child_pkey_workloads() -> Result<(), MprotectError> {
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

fn child_safe_protected_memory() {
    let pkey = ProtectionKey::new(PkeyAccessRights::EnableAccessWrite)
        .map_err(|e| {
            eprintln!("Failed to create ProtectionKey: {:?}", e);
            e
        }).unwrap();
    let mut safe_mem = SafeProtectedMemory::<allocator::Mmap, u32>::new_with_pkey(AccessRights::ReadWrite, &pkey)
        .map_err(|e| {
            eprintln!("Failed to create SafeProtectedMemory: {:?}", e);
            e
        }).unwrap();

    // Write to the protected memory
    println!("Attempt to write the value 42");
    {
        let mut guard = safe_mem.write()
            .map_err(|e| {
                eprintln!("Write access violation: {:?}", e);
                e
            }).unwrap();
        *guard = 42;
    }
    {
        let guard = safe_mem.read()
            .map_err(|e| {
                eprintln!("Read access violation: {:?}", e);
                e
            }).unwrap();
        println!("\tValue written: {}", *guard);
    }
    println!("\tWriting succeeded");

    // Set the pkey to read-only
    //protected_mem.pkey_mprotect(AccessRights::Read)?;
    println!("Set pkey {} to read-only", pkey.key());
    pkey.set_access_rights(PkeyAccessRights::DisableWrite)
        .map_err(|e| {
            eprintln!("Failed to set pkey access rights: {:?}", e);
            e
        }).unwrap();

    // Write to the protected memory (should fail)
    println!("Attempt to read the value");
    {
        let guard = safe_mem.read()
            .map_err(|e| {
                eprintln!("Read access violation: {:?}", e);
                e
            }).unwrap();
        println!("\tValue read: {}", *guard);
    }
    println!("\tReading succeeded");
    println!("Attempt to write the value 84 (this should fail)");
    {
        let mut guard = safe_mem.write()
            .map_err(|e| {
                eprintln!("Write access violation: {:?}", e);
                e
            }).unwrap();
        *guard = 84;
    }
    println!("\tWriting succeeded (this is unexpected!)");
}

fn handle_child_exit(flag: String) {
    // Do workloads in a child process
    let status = Command::new(std::env::current_exe().unwrap())
        .arg(flag)
        .status()
        .expect("Failed to execute child process");

    if let Some(signal) = status.signal() {
        eprintln!("Child process exited with: {}", signal);
        if signal == 11 {
            eprintln!("Segmentation fault occurred as expected");
            return;
        }
        panic!("Child process exited with unexpected signal");
    }
    else if let Some(code) = status.code() {
        if code != 0 {
            panic!("Child process exited with non-zero status: {}", code);
        }
    }
    else {
        panic!("Child process exited in an unexpected way");
    }

    println!("Main thread finished");
}

fn parent_main() {
    println!("Parent process started with PID {}", std::process::id());
    
    println!("--- Testing Protection Key Workloads ---");
    handle_child_exit("--pkeys".to_string());

    println!("--- Testing Safe Protected Memory Workloads ---");
    handle_child_exit("--safe".to_string());

    println!("Parent process finished");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "--pkeys" {
        println!("Child process started with PID {}", std::process::id());
        if let Err(e) = child_pkey_workloads() {
            eprintln!("Child process failed: {}", e);
            std::process::exit(1);
        }
        println!("Child process finished without segmentation fault (this is unexpected!)");
    } else if args.len() > 1 && args[1] == "--safe" {
        println!("Child process started with PID {}", std::process::id());
        child_safe_protected_memory();      // This function handles its own errors and panics on failure
        println!("Child process finished without segmentation fault");
    } else {
        parent_main();
    }
}
