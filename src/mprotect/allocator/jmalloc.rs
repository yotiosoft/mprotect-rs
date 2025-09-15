use super::*;
use jemallocator::Jemalloc;
use std::alloc::{GlobalAlloc, Layout};
use std::ptr::NonNull;

pub struct Jmalloc {
    ptr: *mut u8,
    layout: Layout,
}

impl<T> Allocator<T> for Jmalloc {
    fn allocator_alloc(access_rights: &i32) -> Result<MemoryRegion<Self, T>, AllocatorError> {
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
                access_rights.clone(),
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

    fn allocator_dealloc(&self) -> Result<(), AllocatorError> {
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
