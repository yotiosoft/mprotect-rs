use core::panic;

use libc;
use super::PKey;

use std::ptr::NonNull;

pub mod allocator;

pub mod access_rights;
pub use access_rights::AccessRights;
pub use access_rights::AccessPermissions::*;

/// A memory region that is protected with mprotect/pkey_mprotect.
/// It uses a specified allocator to allocate and deallocate memory.
/// The memory region can optionally be associated with a protection key (pkey).
/// The memory region is automatically deallocated when the `UnsafeProtectedRegion`
/// instance is dropped.
/// `UnsafeProtectedRegion` provides low-level access to the memory region
/// and does not enforce access rights at the Rust type system level.
/// Users must ensure that they respect the access rights set for the memory region.
/// If access rights are violated, it may lead to cause a segmentation fault by the OS.
/// # Type Parameters
/// - `A`: The allocator type that implements the `Allocator<T>` trait.
/// - `T`: The type of data to be stored in the memory region.
/// # Contents
/// - `ptr`: A non-null pointer to the allocated memory region.
/// - `len`: The length of the allocated memory region in bytes.
/// - `pkey_id`: An optional protection key ID associated with the memory region.
/// - `allocator`: The allocator instance used to manage the memory region.
/// - `region_access_rights`: The current access rights of the memory region.
pub struct UnsafeProtectedRegion<A: allocator::Allocator<T>, T> {
    ptr: NonNull<T>,
    len: usize,
    pkey_id: Option<u32>,
    allocator: allocator::MemoryRegion<A, T>,
}

/// Implementation of methods for `UnsafeProtectedRegion`.
impl<A: allocator::Allocator<T>, T> UnsafeProtectedRegion<A, T> {
    /// Allocates a new memory region without associating it with a protection key.
    /// The memory region is allocated with the specified access rights.
    /// # Arguments
    /// - `access_rights`: The access rights to be set for the memory region.
    /// # Returns
    /// - `Ok(UnsafeProtectedRegion)`: On successful allocation.
    /// - `Err(MprotectError)`: If memory allocation fails.
    pub fn new(access_rights: AccessRights) -> Result<Self, super::MprotectError> {
        let allocator = allocator::MemoryRegion::allocate(&access_rights)
            .map_err(|e| super::MprotectError::MemoryAllocationFailed(match e {
                allocator::AllocatorError::MmapFailed(errno) => errno,
                allocator::AllocatorError::MunmapFailed(errno) => errno,
                allocator::AllocatorError::LayoutError => -1,
            }))?;
        Ok(Self {
            ptr: NonNull::new(allocator.ptr() as *mut T).ok_or(super::MprotectError::MemoryAllocationFailed(-1))?,
            len: std::mem::size_of::<T>(),
            pkey_id: None,
            allocator,
        })
    }

    /// Changes the access rights of the memory region by changing the rights
    /// in the page table entries (PTEs).
    /// # Arguments
    /// - `access_rights`: The new access rights to be set for the memory region
    /// using `mprotect`.
    /// # Returns
    /// - `Ok(())`: On successful change of access rights.
    /// - `Err(MprotectError)`: If the `mprotect` system call fails
    pub fn set_access(&self, access_rights: AccessRights) -> Result<(), super::MprotectError> {
        let ret = unsafe {
            libc::mprotect(
                self.ptr.as_ptr() as *mut libc::c_void,
                self.len,
                access_rights.to_i32(),
            )
        };
        if ret != 0 {
            let err_no = std::io::Error::last_os_error().raw_os_error().unwrap();
            return Err(super::MprotectError::MprotectFailed(err_no));
        }
        Ok(())
    }

    /// Changes the access rights of the memory region and associates it with
    /// the specified protection key using the `pkey_mprotect` system call.
    /// # Arguments
    /// - `access_rights`: The new access rights to be set for the memory region
    /// using `pkey_mprotect`.
    /// - `pkey`: A reference to the `PKey` to be associated with
    /// the memory region.
    /// # Returns
    /// - `Ok(())`: On successful change of access rights and association.
    /// - `Err(MprotectError)`: If the `pkey_mprotect` system
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
                access_rights.to_i32(),
                pkey_id
            )
        };
        if ret != 0 {
            let err_no = std::io::Error::last_os_error().raw_os_error().unwrap();
            return Err(super::MprotectError::PkeyMprotectFailed(err_no));
        }
        Ok(())
    }

    /// Changes the access rights of the memory region and associates it with
    /// the specified protection key using the `pkey_mprotect` system call.
    /// # Arguments
    /// - `access_rights`: The new access rights to be set for the memory region
    /// using `pkey_mprotect`.
    /// - `pkey`: A reference to the `PKey` to be associated with
    /// the memory region.
    /// # Returns
    /// - `Ok(())`: On successful change of access rights and association.
    /// - `Err(MprotectError)`: If the `pkey_mprotect` system call fails
    /// or if no protection key is associated with the memory region.
    /// This method updates the internal state of the `UnsafeProtectedRegion`
    /// instance to reflect the new protection key association.
    pub fn set_pkey(&mut self, access_rights: AccessRights, pkey: &PKey) -> Result<(), super::MprotectError> {
        self.pkey_id = Some(pkey.key());
        Self::impl_pkey_mprotect(access_rights, self.ptr.as_ptr() as *mut libc::c_void, self.len, self.pkey_id)
    }

    /// Returns a raw pointer to the allocated memory region.
    /// # Returns
    /// - A mutable raw pointer to the allocated memory region.
    pub fn ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }

    /// Returns the length of the allocated memory region in bytes.
    /// # Returns
    /// - The length of the allocated memory region in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns the protection key ID associated with the memory region, if any.
    /// # Returns
    /// - `Some(u32)`: The protection key ID if associated.
    /// 
    pub fn pkey(&self) -> Option<u32> {
        self.pkey_id
    }

    /// Returns a mutable reference to the data stored in the memory region.
    /// # Returns
    /// - A mutable reference to the data stored in the memory region.
    pub fn as_mut(&mut self) -> &mut T {
        unsafe { &mut *self.ptr.as_ptr() }
    }

    /// Returns a reference to the data stored in the memory region.
    /// # Returns
    /// - A reference to the data stored in the memory region.
    pub fn as_ref(&self) -> &T {
        unsafe { &*self.ptr.as_ptr() }
    }
}

impl<A: allocator::Allocator<T>, T> Drop for UnsafeProtectedRegion<A, T> {
    /// Automatically deallocates the memory region when the `UnsafeProtectedRegion`
    /// instance is dropped. If deallocation fails, it panics with an error message.
    fn drop(&mut self) {
        let ret = self.allocator.deallocate();
        if let Err(e) = ret {
            panic!("Failed to deallocate memory: {:?}", e.to_string());
        }
    }
}
