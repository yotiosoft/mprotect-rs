use super::*;

impl<T> Allocator for ProtectedMemory<T> {
    fn allocate(size: usize, access_rights: i32) -> Result<MemoryRegion<T>, AllocatorError> {
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
        Ok(Self {
            ptr: ptr as *mut T,
            len: alloc_size,
        })
    }

    fn deallocate(ptr: *mut libc::c_void, size: usize) -> Result<(), AllocatorError> {
        mmap::MmapAllocator::deallocate(ptr, size)
    }
    
}
