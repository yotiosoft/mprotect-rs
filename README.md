# mprotect-rs

A Rust library for hardware-enforced memory protection using Intel PKU (Memory Protection Keys). This library provides a type-safe, RAII-based interface to manage memory access permissions at the thread level with extremely low overhead.

## Overview
Traditional memory protection using mprotect requires system calls and TLB flushes, which are expensive. Intel PKU allows userspace applications to change access permissions of memory pages within a few CPU cycles by modifying the PKRU register.

pkeyguard-rs leverages Rust's ownership model and borrow checker to ensure that:

Memory is only accessible when the appropriate guard is in scope.

Read/Write permissions are enforced both at compile-time (via Rust references) and runtime (via Hardware CPU exceptions).

## Features
Zero-cost Abstractions: Direct mapping of PKU instructions to Rust's type system.

RAII Guards: Access rights are automatically revoked when the guard goes out of scope.

Defense in Depth: Even if an attacker bypasses the borrow checker with unsafe code, the hardware (Intel PKU) will trigger a Segmentation Fault if the permissions are not set correctly.

Thread-Local Isolation: Permissions are managed per-thread, as the PKRU register is part of the thread context.

## Usage

Example: Secure Memory Access

```Rust
use pkeyguard::{RegionGuard, PkeyGuard, AccessPermissions, PkeyPermissions, allocator};

fn main() -> Result<(), RuntimeError> {
    // 1. Allocate a memory region via mmap/mprotect
    // Default is ReadWrite, but we will control access via PKU later.
    let mut region = RegionGuard::<allocator::Mmap, u32>::new(AccessPermissions::ReadWrite)
        .map_err(RuntimeError::MprotectError)?;

    // 2. Create a new Protection Key (Pkey)
    // Initially set to NoAccess for maximum security.
    let pkey = PkeyGuard::new(PkeyPermissions::NoAccess)
        .map_err(RuntimeError::MprotectError)?;

    // 3. Associate the region with the Protection Key
    // From here, the hardware enforces access based on the pkey's state.
    let mut associated_region = pkey
        .associate::<PkeyPermissions::NoAccess>(&mut region)
        .map_err(RuntimeError::MprotectError)?;

    // 4. Write access block
    {
        // Temporarily elevate permissions to ReadWrite
        let write_guard = associated_region
            .set_access_rights::<PkeyPermissions::ReadWrite>()
            .map_err(RuntimeError::MprotectError)?;
        
        let mut mut_ref_guard = write_guard.mut_ref_guard()
            .map_err(|e| RuntimeError::PkeyGuardError(e))?;

        *mut_ref_guard = 123; // Safe write
        println!("Value written: {}", *mut_ref_guard);
    } // write_guard drops here, pkey reverts to NoAccess automatically

    // 5. Read-only access block
    {
        let read_guard = associated_region
            .set_access_rights::<PkeyPermissions::ReadOnly>()
            .map_err(RuntimeError::MprotectError)?;
        
        let ref_guard = read_guard.ref_guard()
            .map_err(|e| RuntimeError::PkeyGuardError(e))?;

        println!("Value read: {}", *ref_guard);

        // Hardware Enforcement Example:
        // Even if we use unsafe code to bypass the borrow checker, 
        // the CPU will trigger a Segmentation Fault because the PKRU register
        // is set to ReadOnly.
        /*
        unsafe {
            let mut_ref = ref_guard.ptr() as *mut u32;
            *mut_ref = 789; // CRASH: Segmentation Fault (Hardware-enforced)
        }
        */
    }

    Ok(())
}
```

## How it Works
1. `RegionGuard`: Wraps a memory region allocated via mmap.
1. `PkeyGuard`: Manages the lifecycle of an Intel PKU key (0-15).
1. `Association`: Uses pkey_mprotect to tag specific memory pages with a protection key.
1. `set_access_rights`: Executes the WRPKRU instruction to modify the current thread's access rights. This is much faster than a system call.

## Safety Guarantees
The library uses the Typestate Pattern. You cannot obtain a mutable reference to the protected data unless you have explicitly transitioned the associated_region into a ReadWrite state. This prevents logical errors where memory might be left in an unprotected state.

## Requirements
- CPU: Intel Skylake Scalable or newer (supporting the PKU feature).
- OS: Linux kernel 4.9 or later with CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS enabled.

## License
This project is licensed under the MIT License.
