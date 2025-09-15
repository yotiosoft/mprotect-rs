use libc;
use super::ProtectionKey;

mod allocator;

#[repr(i32)]
pub enum AccessRights {
    None = libc::PROT_NONE,
    Read = libc::PROT_READ,
    Write = libc::PROT_WRITE,
    Exec = libc::PROT_EXEC,
    ReadWrite = libc::PROT_READ | libc::PROT_WRITE,
    ReadExec = libc::PROT_READ | libc::PROT_EXEC,
    WriteExec = libc::PROT_WRITE | libc::PROT_EXEC,
    ReadWriteExec = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
}

pub struct ProtectedMemory<T> {
    ptr: *mut T,
    len: usize,
    pkey: Option<ProtectionKey>,
}

impl<T> ProtectedMemory<T> {
    pub fn with_mprotect(access_rights: AccessRights) -> Result<Self, super::MprotectError> {
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
            return Err(super::MprotectError::MemoryAllocationFailed(err_no));
        }

        Ok(Self {
            ptr: ptr as *mut T,
            len: alloc_size,
            pkey: None,
        })
    }
}

impl<T> Drop for ProtectedMemory<T> {
    fn drop(&mut self) {
        unsafe {
            // drop the inner value
            std::ptr::drop_in_place(self.ptr);
            // unmap the memory
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
    }
}
