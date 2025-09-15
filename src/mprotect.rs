use core::panic;

use libc;
use super::ProtectionKey;

mod allocator;

#[derive(Clone, Copy)]
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
    pkey_id: Option<u32>,
    allocator: allocator::MemoryRegion<allocator::mmap::MmapAllocator, u8>,
}

impl<T> ProtectedMemory<T> {
    pub fn without_pkey(access_rights: AccessRights) -> Result<Self, super::MprotectError> {
        let allocator = allocator::MemoryRegion::allocate(&access_rights)
            .map_err(|e| super::MprotectError::MemoryAllocationFailed(match e {
                allocator::AllocatorError::MmapFailed(errno) => errno,
                allocator::AllocatorError::MunmapFailed(errno) => errno,
            }))?;
        Ok(Self {
            ptr: allocator.ptr() as *mut T,
            len: std::mem::size_of::<T>(),
            pkey_id: None,
            allocator,
        })
    }

    pub fn with_pkey(access_rights: AccessRights, pkey: &ProtectionKey) -> Result<Self, super::MprotectError> {
        let allocator = allocator::MemoryRegion::allocate(&access_rights)
            .map_err(|e| super::MprotectError::MemoryAllocationFailed(match e {
                allocator::AllocatorError::MmapFailed(errno) => errno,
                allocator::AllocatorError::MunmapFailed(errno) => errno,
            }))?;
        // Set the protection key for the allocated memory
        let ret = unsafe {
            libc::syscall(
                libc::SYS_pkey_mprotect,
                allocator.ptr() as *mut libc::c_void,
                allocator.len(),
                access_rights as i32,
                pkey.key(),
            )
        };
        if ret != 0 {
            let err_no = std::io::Error::last_os_error().raw_os_error().unwrap();
            // Clean up allocated memory before returning error
            let _ = allocator.deallocate();
            return Err(super::MprotectError::MemoryAllocationFailed(err_no));
        }
        Ok(Self {
            ptr: allocator.ptr() as *mut T,
            len: std::mem::size_of::<T>(),
            pkey_id: Some(pkey.key()),
            allocator,
        })
    }

    pub fn mprotect(&self, access_rights: AccessRights) -> Result<(), super::MprotectError> {
        let ret = unsafe {
            libc::mprotect(
                self.ptr as *mut libc::c_void,
                self.len,
                access_rights as i32,
            )
        };
        if ret != 0 {
            let err_no = std::io::Error::last_os_error().raw_os_error().unwrap();
            return Err(super::MprotectError::MprotectFailed(err_no));
        }
        Ok(())
    }

    pub fn pkey_mprotect(&self, access_rights: AccessRights) -> Result<(), super::MprotectError> {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_pkey_mprotect,
                self.ptr as *mut libc::c_void,
                self.len,
                access_rights as i32,
                self.pkey_id
            )
        };
        if ret != 0 {
            let err_no = std::io::Error::last_os_error().raw_os_error().unwrap();
            return Err(super::MprotectError::PkeyMprotectFailed(err_no));
        }
        Ok(())
    }

    pub fn ptr(&self) -> *mut T {
        self.ptr
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn pkey(&self) -> Option<u32> {
        self.pkey_id
    }

    pub fn as_mut(&mut self) -> &mut T {
        unsafe { &mut *self.ptr }
    }

    pub fn as_ref(&self) -> &T {
        unsafe { &*self.ptr }
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
