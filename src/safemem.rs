pub use crate::mprotect::*;
pub use crate::pkey::*;

use std::ops::{Deref, DerefMut};

/// Error type for ProtectedMemory operations.
/// Indicates access violations when attempting to read or write protected memory.
/// - ReadAccessViolation: Attempted to read from a memory region without read access.
/// - WriteAccessViolation: Attempted to write to a memory region without write access.
/// - ExecuteAccessViolation: Attempted to execute code in a memory region without execute access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedMemoryError {
    ReadAccessViolation,
    WriteAccessViolation,
}
impl std::fmt::Display for ProtectedMemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtectedMemoryError::ReadAccessViolation => write!(f, "read access violation"),
            ProtectedMemoryError::WriteAccessViolation => write!(f, "write access violation"),
        }
    }
}

/// A memory region that is protected with specific access rights and optionally associated with a protection key (pkey).
/// The memory region can be accessed through guarded read and write methods that enforce the access rights.
/// The memory region is automatically deallocated when the `ProtectedMemory` instance is dropped.
pub struct ProtectedMemory<A: allocator::Allocator<T>, T> {
    memory: UnsafeProtectedRegion<A, T>,
    pkey: Option<PKey>,
    access_rights: AccessRights,  // Cached access rights
}

/// Implementation of ProtectedMemory methods.
impl<A: allocator::Allocator<T>, T> ProtectedMemory<A, T> {
    /// Creates a new `ProtectedMemory` instance without an associated pkey.
    /// The memory region is allocated with the specified access rights.
    /// # Arguments
    /// - `access_rights`: The access rights for the memory region.
    /// # Returns
    /// - `Ok(ProtectedMemory)`: A new `ProtectedMemory` instance if allocation
    /// succeeds.
    /// - `Err(MprotectError)`: An error if allocation fails.
    pub fn new(access_rights: AccessRights) -> Result<Self, super::MprotectError> {
        let memory = UnsafeProtectedRegion::new(access_rights)?;
        Ok(Self { memory, pkey: None , access_rights })
    }

    /// Creates a new `ProtectedMemory` instance associated with the specified pkey.
    /// The memory region is allocated with the specified access rights.
    /// # Arguments
    /// - `access_rights`: The access rights for the memory region.
    /// - `pkey`: The protection key to associate with the memory region.
    /// # Returns
    /// - `Ok(ProtectedMemory)`: A new `ProtectedMemory` instance if allocation
    /// succeeds.
    /// - `Err(MprotectError)`: An error if allocation fails.
    pub fn new_with_pkey(access_rights: AccessRights, pkey: &PKey) -> Result<Self, super::MprotectError> {
        let mut memory = UnsafeProtectedRegion::new(access_rights)?;
        memory.set_pkey(access_rights, pkey)?;
        Ok(Self { memory, pkey: Some(pkey.clone()), access_rights })
    }

    /// Changes the access rights of the memory region.
    /// # Arguments
    /// - `access_rights`: The new access rights for the memory region.
    /// # Returns
    /// - `Ok(())`: If the operation succeeds.
    /// - `Err(MprotectError)`: An error if the operation fails.
    pub fn mprotect(&mut self, access_rights: AccessRights) -> Result<(), super::MprotectError> {
        self.memory.set_access(access_rights)
    }

    /// Returns a mutable reference to the underlying memory.
    pub fn as_mut(&mut self) -> &mut T {
        self.memory.as_mut()
    }

    /// Returns a reference to the underlying memory.
    /// If the memory is associated with a pkey, returns `Some(&PKey)`, otherwise returns `None`.
    pub fn pkey(&self) -> Option<&PKey> {
        self.pkey.as_ref()
    }

    /// Returns the current access rights of the memory region.
    /// The access rights are cached and updated whenever `mprotect` is called.
    /// # Returns
    /// - The current access rights of the memory region.
    pub fn region_access_rights(&self) -> AccessRights {
        self.access_rights
    }

    /// Attempts to read from the protected memory region.
    /// If the memory region has read access, returns a `ReadGuard` that allows safe
    /// reading of the memory.
    /// If the memory region does not have read access, returns a `ProtectedMemoryError::ReadAccessViolation` error.
    /// # Returns
    /// - `Ok(ReadGuard)`: A guard that allows safe reading of the memory
    ///     if read access is allowed.
    /// - `Err(ProtectedMemoryError)`: An error if read access is not allowed
    ///   or if there is another access violation.
    pub fn read(&self) -> Result<ReadGuard<'_, A, T>, super::ProtectedMemoryError> {
        if !self.can_read() {
            return Err(super::ProtectedMemoryError::ReadAccessViolation);
        }
        Ok(ReadGuard { memory: self })
    }

    /// Attempts to write to the protected memory region.
    /// If the memory region has write access, returns a `WriteGuard` that allows safe
    /// writing to the memory.
    /// If the memory region does not have write access, returns a `ProtectedMemoryError::WriteAccessViolation` 
    /// error.
    /// # Returns
    /// - `Ok(WriteGuard)`: A guard that allows safe writing to the
    ///   memory if write access is allowed.
    /// - `Err(ProtectedMemoryError)`: An error if write access is not allowed
    ///  or if there is another access violation.    
    pub fn write(&mut self) -> Result<WriteGuard<'_, A, T>, super::ProtectedMemoryError> {
        if !self.can_write() {
            return Err(super::ProtectedMemoryError::WriteAccessViolation);
        }
        Ok(WriteGuard { memory: self })
    }

    /// Checks if the memory region can be written to based on the current access rights and pkey settings.
    /// # Returns
    /// - `true`: If the memory region can be written to.
    /// - `false`: If the memory region cannot be written to.
    fn can_write(&self) -> bool {
        let mut can_write = true;
        if let Some(pkey) = &self.pkey {
            let pkey_rights = pkey.get_access_rights();
            if pkey_rights == PkeyAccessRights::DisableWrite || pkey_rights == PkeyAccessRights::DisableAccess {
                can_write = false;
            }
        }
        if self.region_access_rights() == AccessRights::Read || self.region_access_rights() == AccessRights::Exec || self.region_access_rights() == AccessRights::ReadExec || self.region_access_rights() == AccessRights::None {
            can_write = false;
        }

        can_write
    }

    /// Checks if the memory region can be read from based on the current access rights and pkey settings.
    /// # Returns
    /// - `true`: If the memory region can be read from.
    /// - `false`: If the memory region cannot be read from.
    fn can_read(&self) -> bool {
        let mut can_read = true;
        if let Some(pkey) = &self.pkey {
            let pkey_rights = pkey.get_access_rights();
            if pkey_rights == PkeyAccessRights::DisableAccess {
                can_read = false;
            }
        }
        if self.region_access_rights() == AccessRights::None || self.region_access_rights() == AccessRights::Exec || self.region_access_rights() == AccessRights::Write || self.region_access_rights() == AccessRights::WriteExec {
            can_read = false;
        }

        can_read
    }
}

/// A guard that provides safe read access to a `ProtectedMemory` instance.
/// This guard ensures that the memory region can be read from based on the current access rights and pkey settings.
pub struct ReadGuard<'a, A: allocator::Allocator<T>, T> {
    memory: &'a ProtectedMemory<A, T>,
}

impl<'a, A: allocator::Allocator<T>, T> Deref for ReadGuard<'a, A, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe {
            self.memory.memory.ptr().as_ref().unwrap()      // NonNull<T>
        }
    }
}

pub struct WriteGuard<'a, A: allocator::Allocator<T>, T> {
    memory: &'a mut ProtectedMemory<A, T>,
}

impl<'a, A: allocator::Allocator<T>, T> Deref for WriteGuard<'a, A, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe {
            self.memory.memory.ptr().as_ref().unwrap()      // NonNull<T>
        }
    }
}

impl<'a, A: allocator::Allocator<T>, T> DerefMut for WriteGuard<'a, A, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            self.memory.memory.ptr().as_mut().unwrap()      // NonNull<T>
        }
    }
}
