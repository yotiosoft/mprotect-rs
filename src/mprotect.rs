use core::panic;

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
    allocator: allocator::MemoryRegion<allocator::mmap::MmapAllocator, u8>,
}

impl<T> ProtectedMemory<T> {
    pub fn with_mprotect(access_rights: AccessRights) -> Result<Self, super::MprotectError> {
        let allocator = allocator::MemoryRegion::allocate(access_rights as i32)
            .map_err(|e| super::MprotectError::MemoryAllocationFailed(match e {
                allocator::AllocatorError::MmapFailed(errno) => errno,
                allocator::AllocatorError::MunmapFailed(errno) => errno,
            }))?;
        Ok(Self {
            ptr: allocator.ptr() as *mut T,
            len: std::mem::size_of::<T>(),
            pkey: None,
            allocator,
        })
    }
}

impl<T> Drop for ProtectedMemory<T> {
    fn drop(&mut self) {
        let ret = self.allocator.deallocate();
        if let Err(e) = ret {
            panic!("Failed to deallocate memory: {:?}", e.to_string());
        }
    }
}
