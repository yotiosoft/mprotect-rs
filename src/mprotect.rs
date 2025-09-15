use core::panic;

use libc;
use super::ProtectionKey;

pub mod allocator;

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

pub enum AllocatorType {
    Mmap,
}

pub struct ProtectedMemory<A: allocator::Allocator<T>, T> {
    ptr: *mut T,
    len: usize,
    pkey_id: Option<u32>,
    allocator: allocator::MemoryRegion<A, T>,
}

impl<A: allocator::Allocator<T>, T> ProtectedMemory<A, T> {
    pub fn without_pkey(access_rights: AccessRights) -> Result<Self, super::MprotectError> {
        let allocator = allocator::MemoryRegion::allocate(&access_rights)
            .map_err(|e| super::MprotectError::MemoryAllocationFailed(match e {
                allocator::AllocatorError::MmapFailed(errno) => errno,
                allocator::AllocatorError::MunmapFailed(errno) => errno,
                allocator::AllocatorError::LayoutError => -1,
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
                allocator::AllocatorError::LayoutError => -1,
            }))?;
        // Set the protection key for the allocated memory
        Self::impl_pkey_mprotect(access_rights, allocator.ptr() as *mut libc::c_void, allocator.len(), Some(pkey.key()))
            .map_err(|e| super::MprotectError::PkeyMprotectFailed(match e {
                super::MprotectError::PkeyMprotectFailed(errno) => errno,
                super::MprotectError::MprotectFailed(errno) => errno,
                super::MprotectError::NoPkeyAssociated => -1,
                _ => -1,
            }))?;
            
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

    fn impl_pkey_mprotect(access_rights: AccessRights, ptr: *mut libc::c_void, len: usize, pkey_id: Option<u32>) -> Result<(), super::MprotectError> {
        if let None = pkey_id {
            return Err(super::MprotectError::NoPkeyAssociated);
        }

        let pkey_id = pkey_id.unwrap();
        let ret = unsafe {
            libc::syscall(
                libc::SYS_pkey_mprotect,
                ptr,
                len,
                access_rights as i32,
                pkey_id
            )
        };
        if ret != 0 {
            let err_no = std::io::Error::last_os_error().raw_os_error().unwrap();
            return Err(super::MprotectError::PkeyMprotectFailed(err_no));
        }
        Ok(())
    }

    pub fn pkey_mprotect(&mut self, access_rights: AccessRights, pkey: &ProtectionKey) -> Result<(), super::MprotectError> {
        self.pkey_id = Some(pkey.key());
        Self::impl_pkey_mprotect(access_rights, self.ptr as *mut libc::c_void, self.len, self.pkey_id)
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

impl<A: allocator::Allocator<T>, T> Drop for ProtectedMemory<A, T> {
    fn drop(&mut self) {
        let ret = self.allocator.deallocate();
        if let Err(e) = ret {
            panic!("Failed to deallocate memory: {:?}", e.to_string());
        }
    }
}
