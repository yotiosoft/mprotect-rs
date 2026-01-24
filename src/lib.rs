//! A Rust library for memory protection using `mprotect` and Intel Memory Protection Keys (MPK).
//! 
//! This library provides safe abstractions for controlling memory access permissions at runtime,
//! offering both traditional `mprotect`-based memory protection and modern protection key-based
//! access control for fine-grained memory security.
//! 
//! # Features
//! 
//! - **Memory Protection**: Use `mprotect` to set page-level access permissions (read, write, execute)
//! - **Protection Keys (pkey)**: Leverage Intel MPK for thread-local memory access control
//! - **Guard Types**: Type-safe memory regions with automatic permission management
//! - **Multiple Allocators**: Support for both `mmap` and `jemalloc` allocation strategies

mod mpk;
pub use mpk::*;

mod mprotect;
pub use mprotect::*;

mod pkeyguard;
pub use pkeyguard::*;

mod regionguard;
pub use regionguard::*;

/// Type alias for system error numbers.
pub type Errno = i32;

use std::fmt::Display;

/// Errors that can occur during memory protection operations.
/// 
/// This enum represents all possible failure modes when working with protected memory regions,
/// including allocation failures, permission changes, and protection key operations.
#[derive(Debug)]
pub enum MprotectError {
    /// Protection key allocation failed.
    /// 
    /// This error occurs when the `pkey_alloc` system call fails.
    /// Common causes include:
    /// - System does not support protection keys
    /// - All available protection keys are already allocated
    /// - Invalid flags or access rights
    PkeyAllocFailed(Errno),
    
    /// Memory allocation failed.
    /// 
    /// This error occurs when the underlying allocator (mmap or jemalloc) fails to allocate memory.
    /// Common causes include:
    /// - Insufficient memory available
    /// - Invalid allocation size or alignment
    /// - System resource limits reached
    MemoryAllocationFailed(Errno),
    
    /// Memory deallocation failed.
    /// 
    /// This error occurs when freeing memory fails.
    /// Common causes include:
    /// - Invalid memory address
    /// - Double free attempt
    /// - Memory corruption
    MemoryDeallocationFailed(Errno),
    
    /// The `mprotect` system call failed.
    /// 
    /// This error occurs when changing page-level access permissions fails.
    /// Common causes include:
    /// - Invalid memory address or size
    /// - Attempting to set incompatible permissions
    /// - Memory region is not page-aligned
    MprotectFailed(Errno),
    
    /// The `pkey_mprotect` system call failed.
    /// 
    /// This error occurs when associating a protection key with a memory region fails.
    /// Common causes include:
    /// - Invalid protection key
    /// - System does not support protection keys
    /// - Memory region is not page-aligned
    PkeyMprotectFailed(Errno),
    
    /// No protection key is associated with the memory region.
    /// 
    /// This error occurs when attempting to perform an operation that requires
    /// a protection key, but the memory region has no associated key.
    NoPkeyAssociated,
}

impl Display for MprotectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MprotectError::PkeyAllocFailed(errno) => write!(f, "pkey allocation failed with errno {}", errno),
            MprotectError::MemoryAllocationFailed(errno) => write!(f, "memory allocation failed with errno {}", errno),
            MprotectError::MemoryDeallocationFailed(errno) => write!(f, "memory deallocation failed with errno {}", errno),
            MprotectError::MprotectFailed(errno) => write!(f, "mprotect failed with errno {}", errno),
            MprotectError::PkeyMprotectFailed(errno) => write!(f, "pkey mprotect failed with errno {}", errno),
            MprotectError::NoPkeyAssociated => write!(f, "no protection key associated with the memory region"),
        }
    }
}
