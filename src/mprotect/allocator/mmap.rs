use super::*;
use libc;

pub struct MmapAllocator {
    ptr: *mut libc::c_void,
    size: usize,
}

impl<T> Allocator<T> for MmapAllocator {
    fn allocator_alloc(access_rights: i32) -> Result<MemoryRegion<Self, T>, AllocatorError> {
        let page_size = unsafe {
            libc::sysconf(libc::_SC_PAGESIZE) as usize
        };
        let alloc_size = ((std::mem::size_of::<T>() + page_size - 1) / page_size) * page_size;
    
        // Allocate anonymous memory
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                alloc_size,
                access_rights as i32,
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
            ptr: ptr as *mut T, 
            len: alloc_size, 
            allocator: MmapAllocator { ptr, size: alloc_size }
        })
    }

    fn allocator_dealloc(&self) -> Result<(), AllocatorError> {
        // drop the inner value
        unsafe {
            std::ptr::drop_in_place(self.ptr);
        }
        // unmap the memory
        let ret = unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.size)
        };
        if ret != 0 {
            let err_no = std::io::Error::last_os_error().raw_os_error().unwrap();
            return Err(super::AllocatorError::MunmapFailed(err_no));
        }
        Ok(())
    }
    
}
