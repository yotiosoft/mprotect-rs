//! Memory allocators for protected memory regions.
//! 
//! This module provides different allocation strategies for memory regions that can be
//! protected with `mprotect` or `pkey_mprotect`. Each allocator has different characteristics
//! and use cases.

use libc;
use std::fmt::Display;
use std::ptr::NonNull;

mod mmap;
pub use mmap::Mmap;

mod jmalloc;
pub use jmalloc::Jmalloc;

/// Errors that can occur during memory allocation or deallocation.
#[repr(i32)]
pub enum AllocatorError {
    /// The `mmap` system call failed.
    /// 
    /// This error occurs when `mmap` fails to allocate memory. Common causes include:
    /// - Insufficient memory available
    /// - Invalid flags or protection bits
    /// - System resource limits reached
    MmapFailed(i32),
    
    /// The `munmap` system call failed.
    /// 
    /// This error occurs when `munmap` fails to deallocate memory. Common causes include:
    /// - Invalid memory address
    /// - Memory region was not allocated with `mmap`
    /// - Double free attempt
    MunmapFailed(i32),
    
    /// Memory layout error.
    /// 
    /// This error occurs when creating a memory layout fails, typically due to
    /// invalid size or alignment requirements.
    LayoutError,
}

impl Display for AllocatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AllocatorError::MmapFailed(errno) => write!(f, "mmap failed with errno {}", errno),
            AllocatorError::MunmapFailed(errno) => write!(f, "munmap failed with errno {}", errno),
            AllocatorError::LayoutError => write!(f, "layout error"),
        }
    }
}

/// A memory region allocated by a specific allocator.
/// 
/// This struct wraps the allocated memory and provides methods to access
/// and deallocate it. It is generic over the allocator type and the data type.
/// 
/// # Type Parameters
/// 
/// - `A`: The allocator type that implements the `Allocator<T>` trait
/// - `T`: The type of data to be stored in the memory region
pub struct MemoryRegion<A: Allocator<T>, T> {
    ptr: NonNull<T>,
    len: usize,
    allocator: A,
}

/// Trait for memory allocators that can allocate and deallocate memory regions.
/// 
/// Implementors of this trait provide specific allocation strategies (e.g., `mmap`, `jemalloc`)
/// that can be used with protected memory regions.
/// 
/// # Safety
/// 
/// All methods in this trait are unsafe because they directly manage memory allocation
/// and deallocation, which requires careful handling to avoid memory leaks and corruption.
pub trait Allocator<T> {
    /// Allocates a new memory region with the specified protection flags.
    /// 
    /// # Safety
    /// 
    /// This function is unsafe because it directly allocates memory that must be
    /// properly managed and eventually deallocated.
    /// 
    /// # Arguments
    /// 
    /// - `prot`: The protection flags to be set for the memory region (e.g., `PROT_READ`, `PROT_WRITE`)
    /// 
    /// # Returns
    /// 
    /// - `Ok(MemoryRegion)`: On successful allocation
    /// - `Err(AllocatorError)`: If allocation fails
    unsafe fn allocator_alloc(prot: &i32) -> Result<MemoryRegion<Self, T>, AllocatorError>
    where
        Self: Sized;

    /// Deallocates the memory region.
    /// 
    /// # Safety
    /// 
    /// This function is unsafe because it frees memory that must not be accessed
    /// after deallocation. Double-free will cause undefined behavior.
    /// 
    /// # Returns
    /// 
    /// - `Ok(())`: On successful deallocation
    /// - `Err(AllocatorError)`: If deallocation fails
    unsafe fn allocator_dealloc(&self) -> Result<(), AllocatorError>;
}

impl<A: Allocator<T>, T> MemoryRegion<A, T> {
    /// Allocates a new memory region using the specified allocator.
    /// 
    /// This method delegates to the allocator's `allocator_alloc` method to perform
    /// the actual allocation.
    /// 
    /// # Safety
    /// 
    /// This function is unsafe because it allocates uninitialized memory.
    /// 
    /// # Arguments
    /// 
    /// - `access_rights`: The access rights to be set for the memory region
    /// 
    /// # Returns
    /// 
    /// - `Ok(MemoryRegion)`: On successful allocation
    /// - `Err(AllocatorError)`: If allocation fails
    pub unsafe fn allocate(access_rights: &super::AccessRights) -> Result<Self, AllocatorError> {
        let access_rights = access_rights.to_i32();
        A::allocator_alloc(&access_rights)
    }
    
    /// Deallocates the memory region.
    /// 
    /// This method delegates to the allocator's `allocator_dealloc` method to perform
    /// the actual deallocation.
    /// 
    /// # Safety
    /// 
    /// This function is unsafe because it frees memory that must not be accessed after deallocation.
    /// 
    /// # Returns
    /// 
    /// - `Ok(())`: On successful deallocation
    /// - `Err(AllocatorError)`: If deallocation fails
    pub unsafe fn deallocate(&self) -> Result<(), AllocatorError> {
        self.allocator.allocator_dealloc()
    }
    
    /// Returns a raw pointer to the allocated memory.
    /// 
    /// # Returns
    /// 
    /// A mutable raw pointer to the allocated memory region.
    pub fn ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }
    
    /// Returns the size of the allocated memory region in bytes.
    /// 
    /// # Returns
    /// 
    /// The size of the allocated memory region in bytes.
    pub fn len(&self) -> usize {
        self.len
    }
}
