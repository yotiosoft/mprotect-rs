use super::*;
use libc;

/// Memory allocator using the `mmap` system call.
/// 
/// This allocator uses `mmap` with anonymous memory mapping to allocate page-aligned
/// memory regions. This is the recommended allocator for use with `mprotect` and
/// `pkey_mprotect` as it guarantees page alignment and allows direct control over
/// protection flags.
/// 
/// # Characteristics
/// 
/// - **Page-aligned**: Memory is always aligned to page boundaries (typically 4KB)
/// - **Efficient for mprotect**: Direct support for memory protection flags
/// - **System-level**: Memory is allocated directly from the operating system
/// - **Large allocations**: Suitable for any size, but more efficient for larger allocations
pub struct Mmap {
    ptr: *mut libc::c_void,
    size: usize,
}

impl<T> Allocator<T> for Mmap {
    /// Allocates memory using `mmap` with the specified protection flags.
    /// 
    /// This method allocates page-aligned anonymous memory that can be used with
    /// `mprotect` and `pkey_mprotect`. The size is rounded up to the nearest page size.
    /// 
    /// # Safety
    /// 
    /// This function is unsafe because it allocates uninitialized memory.
    /// 
    /// # Arguments
    /// 
    /// - `access_rights`: The initial protection flags for the memory region
    /// 
    /// # Returns
    /// 
    /// - `Ok(MemoryRegion)`: On successful allocation
    /// - `Err(AllocatorError::MmapFailed)`: If the `mmap` system call fails
    unsafe fn allocator_alloc(access_rights: &i32) -> Result<MemoryRegion<Self, T>, AllocatorError> {
        let page_size = unsafe {
            libc::sysconf(libc::_SC_PAGESIZE) as usize
        };
        let alloc_size = ((std::mem::size_of::<T>() + page_size - 1) / page_size) * page_size;
    
        // Allocate anonymous memory
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                alloc_size,
                *access_rights,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            let err_no = std::io::Error::last_os_error().raw_os_error().unwrap();
            return Err(super::AllocatorError::MmapFailed(err_no));
        }
        Ok(MemoryRegion { 
            ptr: NonNull::new(ptr as *mut T).ok_or(super::AllocatorError::MmapFailed(-1))?, 
            len: alloc_size, 
            allocator: Mmap { ptr, size: alloc_size }
        })
    }

    /// Deallocates memory using `munmap`.
    /// 
    /// This method unmaps the memory region that was previously allocated with `mmap`.
    /// 
    /// # Safety
    /// 
    /// This function is unsafe because it frees memory that must not be accessed after deallocation.
    /// 
    /// # Returns
    /// 
    /// - `Ok(())`: On successful deallocation
    /// - `Err(AllocatorError::MunmapFailed)`: If the `munmap` system call fails
    unsafe fn allocator_dealloc(&self) -> Result<(), AllocatorError> {
        // drop the inner value
        unsafe {
            std::ptr::drop_in_place(self.ptr);
        }
        // unmap the memory
        let ret = unsafe {
            libc::munmap(self.ptr, self.size)
        };
        if ret != 0 {
            let err_no = std::io::Error::last_os_error().raw_os_error().unwrap();
            return Err(super::AllocatorError::MunmapFailed(err_no));
        }
        Ok(())
    }
}
