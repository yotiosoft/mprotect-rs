use super::*;
use jemallocator::Jemalloc;
use std::alloc::{GlobalAlloc, Layout};
use std::ptr::NonNull;

/// Memory allocator using jemalloc.
/// 
/// This allocator uses the jemalloc memory allocator to allocate memory regions,
/// then applies `mprotect` to set the desired protection flags. Unlike `Mmap`,
/// this allocator is not guaranteed to be page-aligned initially, but memory
/// protection is still applied after allocation.
/// 
/// # Characteristics
/// 
/// - **Heap-based**: Memory is allocated from the heap using jemalloc
/// - **Flexible size**: More efficient for small allocations compared to `Mmap`
/// - **Secondary mprotect**: Requires additional `mprotect` call after allocation
/// - **Not guaranteed page-aligned**: May require alignment adjustments for some use cases
/// 
/// # Note
/// 
/// This allocator is experimental and may have limitations when used with
/// protection keys, as jemalloc-allocated memory might not always be page-aligned.
/// For most use cases with `mprotect` and `pkey_mprotect`, prefer using `Mmap`.
pub struct Jmalloc {
    ptr: *mut u8,
    layout: Layout,
}

impl<T> Allocator<T> for Jmalloc {
    /// Allocates memory using jemalloc and applies `mprotect`.
    /// 
    /// This method first allocates memory using jemalloc's global allocator,
    /// then applies the specified protection flags using `mprotect`.
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
    /// - `Err(AllocatorError::MmapFailed)`: If memory allocation or `mprotect` fails
    unsafe fn allocator_alloc(access_rights: &i32) -> Result<MemoryRegion<Self, T>, AllocatorError> {
        let alloc_size = std::mem::size_of::<T>();
        let layout = Layout::from_size_align(alloc_size, std::mem::align_of::<T>())
            .map_err(|_| super::AllocatorError::LayoutError)?;
    
        // Allocate anonymous memory
        let ptr = unsafe {
            Jemalloc.alloc_zeroed(
                layout
            )
        };
        if ptr.is_null() {
            let err_no = std::io::Error::last_os_error().raw_os_error().unwrap();
            return Err(super::AllocatorError::MmapFailed(err_no));
        }
        
        // Set memory protection
        let ret = unsafe {
            libc::mprotect(
                ptr as *mut libc::c_void,
                alloc_size,
                *access_rights,
            )
        };
        if ret != 0 {
            let err_no = std::io::Error::last_os_error().raw_os_error().unwrap();
            unsafe {
                Jemalloc.dealloc(ptr, layout);
            }
            return Err(super::AllocatorError::MmapFailed(err_no));
        }

        Ok(MemoryRegion { 
            ptr: NonNull::new(ptr as *mut T).ok_or(super::AllocatorError::MmapFailed(-1))?, 
            len: alloc_size, 
            allocator: Jmalloc { ptr, layout }
        })
    }

    /// Deallocates memory using jemalloc.
    /// 
    /// This method frees the memory that was previously allocated with jemalloc.
    /// 
    /// # Safety
    /// 
    /// This function is unsafe because it frees memory that must not be accessed after deallocation.
    /// 
    /// # Returns
    /// 
    /// - `Ok(())`: Always returns `Ok` as jemalloc deallocation does not fail
    unsafe fn allocator_dealloc(&self) -> Result<(), AllocatorError> {
        // drop the inner value
        unsafe {
            std::ptr::drop_in_place(self.ptr);
        }
        // unmap the memory
        unsafe {
            Jemalloc.dealloc(self.ptr, self.layout)
        };
        Ok(())
    }
}
