use mprotect_rs::*;

use std::process::Command;
use std::os::unix::process::ExitStatusExt;

#[derive(Debug)]
enum RuntimeError {
    MprotectError(MprotectError),
    SafeProtectedMemoryError(SafeProtectedMemoryError),
    UnexpectedSuccess,  // For cases where we expect a failure but got success
}
impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeError::MprotectError(e) => write!(f, "MprotectError: {}", e),
            RuntimeError::SafeProtectedMemoryError(e) => write!(f, "SafeProtectedMemoryError: {}", e),
            RuntimeError::UnexpectedSuccess => write!(f, "Operation succeeded unexpectedly"),
        }
    }
}

fn child_pkey_workloads() -> Result<(), RuntimeError> {
    let pkey = ProtectionKey::new(PkeyAccessRights::EnableAccessWrite).map_err(RuntimeError::MprotectError)?;
    let mut protected_mem = ProtectedMemory::<allocator::Mmap, u32>::with_pkey(AccessRights::ReadWrite, &pkey).map_err(RuntimeError::MprotectError)?;

    //let mut protected_mem = ProtectedMemory::<u32>::without_pkey(AccessRights::Read)?;

    // Write to the protected memory
    println!("\tAttempt to write the value 42");
    *protected_mem.as_mut() = 42;
    println!("\t\tValue written: {}", *protected_mem.as_ref());
    println!("\t\tWriting succeeded");

    // Set the pkey to read-only
    //protected_mem.pkey_mprotect(AccessRights::Read)?;
    println!("\tSet pkey {} to read-only", pkey.key());
    pkey.set_access_rights(PkeyAccessRights::DisableWrite).map_err(RuntimeError::MprotectError)?;

    // Read from the protected memory
    println!("\tAttempt to read the value");
    println!("\t\tValue read: {}", *protected_mem.as_ref());
    println!("\t\tReading succeeded");

    // Create another pkey and allocate another memory region with it
    println!("\tAttempt to create another pkey and allocate memory with it");
    let pkey2 = ProtectionKey::new(PkeyAccessRights::EnableAccessWrite).map_err(RuntimeError::MprotectError)?;
    println!("\t\tCreated another pkey {}", pkey2.key());
    let mut new_memory = ProtectedMemory::<allocator::Jmalloc, u32>::with_pkey(AccessRights::ReadWrite, &pkey2).map_err(RuntimeError::MprotectError)?;
    println!("\tSet the value in pkey {} memory to 100", pkey2.key());
    *new_memory.as_mut() = 100;
    println!("\t\tValue in new memory: {}", *new_memory.as_ref());
    println!("\t\tWriting to new memory succeeded");

    // Create another pkey and switch the pkey of the existing memory region to it
    println!("\tAttempt to create another pkey and switch the existing memory to it");
    let pkey3 = ProtectionKey::new(PkeyAccessRights::DisableWrite).map_err(RuntimeError::MprotectError)?;
    println!("\t\tCreated another pkey {}", pkey3.key());
    protected_mem.pkey_mprotect(AccessRights::Read, &pkey3).map_err(RuntimeError::MprotectError)?;
    println!("\tSwitched the existing memory (before: pkey {}, now: pkey {})", pkey.key(), pkey3.key());

    // Read from the memory region (should succeed)
    println!("\tAttempt to read the value");
    println!("\t\tValue read: {}", *protected_mem.as_ref());
    println!("\t\tReading succeeded");

    // Write to the memory region (should fail)
    println!("\tAttempt to write the value 84 (this will likely cause a segmentation fault!)");
    *protected_mem.as_mut() = 84;
    println!("\t\tValue written: {}", *protected_mem.as_ref());
    println!("\t\tWriting succeeded (this is unexpected!)");

    // Set the pkey 1 to no access
    //protected_mem.pkey_mprotect(AccessRights::None)?;
    println!("\tSet pkey {} to no access", pkey.key());
    pkey.set_access_rights(PkeyAccessRights::DisableAccess).map_err(RuntimeError::MprotectError)?;

    // This will likely cause a segmentation fault
    println!("\tAttempt to read the value again (this will likely cause a segmentation fault!)");
    println!("\t\tValue read: {}", *protected_mem.as_ref());
    println!("\t\tReading succeeded (this is unexpected!)");

    Err(RuntimeError::UnexpectedSuccess)
}

fn child_safe_protected_memory() -> Result<(), RuntimeError> {
    let pkey = ProtectionKey::new(PkeyAccessRights::EnableAccessWrite).map_err(RuntimeError::MprotectError)?;
    let mut safe_mem = SafeProtectedMemory::<allocator::Mmap, u32>::new_with_pkey(AccessRights::ReadWrite, &pkey).map_err(RuntimeError::MprotectError)?;

    // Write to the protected memory
    println!("\tAttempt to write the value 42");
    {
        let mut guard = safe_mem.write().map_err(RuntimeError::SafeProtectedMemoryError)?;
        *guard = 42;
    }
    {
        let guard = safe_mem.read().map_err(RuntimeError::SafeProtectedMemoryError)?;
        println!("\tValue written: {}", *guard);
    }
    println!("\t\tWriting succeeded");

    // Set the pkey to read-only
    //protected_mem.pkey_mprotect(AccessRights::Read)?;
    println!("\tSet pkey {} to read-only", pkey.key());
    pkey.set_access_rights(PkeyAccessRights::DisableWrite).map_err(RuntimeError::MprotectError)?;

    // Write to the protected memory (should fail)
    println!("\tAttempt to read the value");
    {
        let guard = safe_mem.read().map_err(RuntimeError::SafeProtectedMemoryError)?;
        println!("\tValue read: {}", *guard);
    }
    println!("\t\tReading succeeded");
    println!("\tAttempt to write the value 84 (this should fail)");
    {
        let mut guard = safe_mem.write().map_err(RuntimeError::SafeProtectedMemoryError)?;
        *guard = 84;
    }
    println!("\t\tWriting succeeded (this is unexpected!)");

    Err(RuntimeError::UnexpectedSuccess)
}

fn child_safe_guarded_pkey() -> Result<(), RuntimeError> {
    let pkey = ProtectionKey::new(PkeyAccessRights::EnableAccessWrite).map_err(RuntimeError::MprotectError)?;
    let mut safe_mem = SafeProtectedMemory::<allocator::Mmap, u32>::new_with_pkey(AccessRights::ReadWrite, &pkey).map_err(RuntimeError::MprotectError)?;

    {
        println!("\tCreating GuardedProtectionKey to set pkey to DisableWrite");
        let _guarded_pkey = GuardedProtectionKey::new(&pkey, PkeyAccessRights::DisableWrite).map_err(RuntimeError::MprotectError)?;
        println!("\tAttempt to read the value (should succeed)");
        {
            let guard = safe_mem.read().map_err(RuntimeError::SafeProtectedMemoryError)?;
            println!("\t\tValue read: {}", *guard);
        }

        {   // This inner scope is to test nested GuardedProtectionKey. The rights will be EnableAccessWrite here.
            println!("\tCreating GuardedProtectionKey to set pkey to EnableAccessWrite");
            let _inner_guarded_pkey = GuardedProtectionKey::new(&pkey, PkeyAccessRights::EnableAccessWrite).map_err(RuntimeError::MprotectError)?;
            println!("\tAttempt to write the value 84 (should succeed)");
            {
                let mut guard = safe_mem.write().map_err(RuntimeError::SafeProtectedMemoryError)?;
                *guard = 84;
                println!("\t\tValue written: {}", *guard);
            }
        }   // End of the inner scope. The rights should revert back to DisableWrite here.

        println!("\tOut of inner GuardedProtectionKey scope, pkey should be back to DisableWrite");
        println!("\tAttempt to write the value 168 (should fail)");
        {
            let mut guard = safe_mem.write().map_err(RuntimeError::SafeProtectedMemoryError)?;
            *guard = 168;
            println!("\tValue written: {}", *guard);
        }
    }

    Err(RuntimeError::UnexpectedSuccess)
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
        eprintln!("Child process exited due to signal: {}", signal);
    }
    else if let Some(code) = status.code() {
        if code != 0 {
            eprintln!("Child process exited with non-zero status: {}", code);
        }
    }
    else {
        eprintln!("Child process exited in an unexpected way");
    }

    println!("Main thread finished");
}

fn parent_main() {
    println!("Parent process started with PID {}", std::process::id());
    
    println!("--- Testing Protection Key Workloads ---");
    handle_child_exit("--pkeys".to_string());

    println!("--- Testing Safe Protected Memory Workloads ---");
    handle_child_exit("--safe".to_string());

    println!("--- Testing Safe Guarded Pkey Workloads ---");
    handle_child_exit("--safe-guarded-pkey".to_string());

    println!("Parent process finished");
}

fn main() -> Result<(), RuntimeError> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "--pkeys" {
        println!("Child process started with PID {}", std::process::id());
        child_pkey_workloads()?;      // This function handles its own errors and panics on failure
        println!("Child process finished without segmentation fault (this is unexpected!)");
    } else if args.len() > 1 && args[1] == "--safe" {
        println!("Child process started with PID {}", std::process::id());
        child_safe_protected_memory()?;      // This function handles its own errors and panics on failure
        println!("Child process finished without segmentation fault");
    } else if args.len() > 1 && args[1] == "--safe-guarded-pkey" {
        println!("Child process started with PID {}", std::process::id());
        child_safe_guarded_pkey()?;      // This function handles its own errors and panics on failure
        println!("Child process finished without segmentation fault");
    } else {
        parent_main();
    }

    Ok(())
}
