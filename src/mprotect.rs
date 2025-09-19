use core::panic;

use libc;
use super::PKey;

use std::{io::Read, ptr::NonNull};
use bitflags::bitflags;

pub mod allocator;

/// Memory protection flags.
/// These correspond to the Page Table Entry (PTE) flags.
/// - `None`: No access.
/// - `Read`: Read-only access.
/// - `Write`: Write-only access.
/// - `Exec`: Execute-only access.
/// - `ReadWrite`: Read and write access.
/// - `ReadExec`: Read and execute access.
/// - `WriteExec`: Write and execute access.
/// - `ReadWriteExec`: Read, write, and execute access.
//#[derive(Clone, Copy, Debug, PartialEq, Eq)]
//#[repr(i32)]
bitflags! {
    /// Memory protection flags represented as bitflags.
    /// These correspond to the Page Table Entry (PTE) flags.
    /// - `NONE`: No access.
    /// - `READ`: Read-only access.
    /// - `WRITE`: Write-only access.
    /// - `EXEC`: Execute-only access.
    /// - `READ_WRITE`: Read and write access.
    /// - `READ_EXEC`: Read and execute access.
    /// - `WRITE_EXEC`: Write and execute access.
    /// - `READ_WRITE_EXEC`: Read, write, and execute access.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AccessRights: i32 {
        const NONE = libc::PROT_NONE;
        const READ = libc::PROT_READ;
        const WRITE = libc::PROT_WRITE;
        const EXEC = libc::PROT_EXEC;
        const READ_WRITE = libc::PROT_READ | libc::PROT_WRITE;
        const READ_EXEC = libc::PROT_READ | libc::PROT_EXEC;
        const WRITE_EXEC = libc::PROT_WRITE | libc::PROT_EXEC;
        const READ_WRITE_EXEC = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
    }
}

impl AccessRights {
    /// Add the specified access right to the current access rights.
    /// # Arguments
    /// - `right`: The access right to add.
    /// # Returns
    /// - The new access rights with the specified access right added.
    pub fn add(&self, right: AccessRights) -> AccessRights {
        AccessRights::from_bits_truncate(self.bits() | right.bits())
    }

    /// Removes the specified access right from the current access rights.
    /// # Arguments
    /// - `right`: The access right to remove.
    /// # Returns
    /// - The new access rights with the specified access right deleted.
    pub fn minus(&self, right: AccessRights) -> AccessRights {
        AccessRights::from_bits_truncate(self.bits() & !right.bits())
    }

    /// Checks if the current access rights contain the specified access right.
    /// # Arguments
    /// - `right`: The access right to check for.
    /// # Returns
    /// - `true`: If the current access rights contain the specified access right.
    /// - `false`: Otherwise.
    pub fn has(&self, right: AccessRights) -> bool {
        self.bits() & right.bits() == right.bits()
    }

    /// Convert the access rights to an i32 representation.
    /// # Returns
    /// - The i32 representation of the access rights.
    pub fn to_i32(&self) -> i32 {
        self.bits()
    }
}

#[derive(Copy, Clone)]
pub struct NoAccess;
#[derive(Copy, Clone)]
pub struct ReadOnly;
#[derive(Copy, Clone)]
pub struct WriteOnly;
#[derive(Copy, Clone)]
pub struct ExecuteOnly;
#[derive(Copy, Clone)]
pub struct ReadWrite;
#[derive(Copy, Clone)]
pub struct ReadExecute;
#[derive(Copy, Clone)]
pub struct WriteExecute;
#[derive(Copy, Clone)]
pub struct ReadWriteExecute;

pub trait AccessValue {
    fn value(&self) -> AccessRights; 
}

impl AccessValue for NoAccess {  fn value(&self) -> AccessRights { AccessRights::NONE } }
impl AccessValue for ReadOnly { fn value(&self) -> AccessRights { AccessRights::READ } }
impl AccessValue for WriteOnly { fn value(&self) -> AccessRights { AccessRights::WRITE } }
impl AccessValue for ExecuteOnly { fn value(&self) -> AccessRights { AccessRights::EXEC } }
impl AccessValue for ReadWrite { fn value(&self) -> AccessRights { AccessRights::READ_WRITE } }
impl AccessValue for ReadExecute { fn value(&self) -> AccessRights { AccessRights::READ_EXEC } }
impl AccessValue for WriteExecute { fn value(&self) -> AccessRights { AccessRights::WRITE_EXEC } }
impl AccessValue for ReadWriteExecute { fn value(&self) -> AccessRights { AccessRights::READ_WRITE_EXEC } }

pub trait ReadAllowed: AccessValue {}
impl ReadAllowed for ReadOnly {}
impl ReadAllowed for ReadWrite {}
impl ReadAllowed for ReadExecute {}
impl ReadAllowed for ReadWriteExecute {}

pub trait WriteAllowed: AccessValue {}
impl WriteAllowed for WriteOnly {}
impl WriteAllowed for ReadWrite {}
impl WriteAllowed for WriteExecute {}
impl WriteAllowed for ReadWriteExecute {}

pub trait ExecuteAllowed: AccessValue {}
impl ExecuteAllowed for ExecuteOnly {}
impl ExecuteAllowed for ReadExecute {}
impl ExecuteAllowed for WriteExecute {}
impl ExecuteAllowed for ReadWriteExecute {}

pub trait NoAccessAllowed: AccessValue {}
impl NoAccessAllowed for NoAccess {}

pub trait AllAccesses { fn value(&self) -> AccessRights; }
impl AllAccesses for NoAccess { fn value(&self) -> AccessRights { AccessRights::NONE } }
impl AllAccesses for ReadOnly { fn value(&self) -> AccessRights { AccessRights::READ } }
impl AllAccesses for WriteOnly { fn value(&self) -> AccessRights { AccessRights::WRITE } }
impl AllAccesses for ExecuteOnly { fn value(&self) -> AccessRights { AccessRights::EXEC } }
impl AllAccesses for ReadWrite { fn value(&self) -> AccessRights { AccessRights::READ_WRITE } }
impl AllAccesses for ReadExecute { fn value(&self) -> AccessRights { AccessRights::READ_EXEC } }
impl AllAccesses for WriteExecute { fn value(&self) -> AccessRights { AccessRights::WRITE_EXEC } }
impl AllAccesses for ReadWriteExecute { fn value(&self) -> AccessRights { AccessRights::READ_WRITE_EXEC } }

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
