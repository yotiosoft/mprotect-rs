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
    ExecuteAccessViolation,
}
impl std::fmt::Display for ProtectedMemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtectedMemoryError::ReadAccessViolation => write!(f, "read access violation"),
            ProtectedMemoryError::WriteAccessViolation => write!(f, "write access violation"),
            ProtectedMemoryError::ExecuteAccessViolation => write!(f, "execute access violation"),
        }
    }
}

pub struct ProtectedMemory<A: allocator::Allocator<T>, T> {
    memory: UnProtectedMemory<A, T>,
    pkey: Option<PKey>,
}

impl<A: allocator::Allocator<T>, T> ProtectedMemory<A, T> {
    pub fn new(access_rights: AccessRights) -> Result<Self, super::MprotectError> {
        let memory = UnProtectedMemory::without_pkey(access_rights)?;
        Ok(Self { memory, pkey: None })
    }

    pub fn new_with_pkey(access_rights: AccessRights, pkey: &PKey) -> Result<Self, super::MprotectError> {
        let memory = UnProtectedMemory::with_pkey(access_rights, pkey)?;
        Ok(Self { memory, pkey: Some(pkey.clone()) })
    }

    pub fn mprotect(&self, access_rights: AccessRights) -> Result<(), super::MprotectError> {
        self.memory.mprotect(access_rights)
    }

    pub fn as_mut(&mut self) -> &mut T {
        self.memory.as_mut()
    }

    pub fn pkey(&self) -> Option<&PKey> {
        self.pkey.as_ref()
    }

    pub fn region_access_rights(&self) -> AccessRights {
        self.memory.region_access_rights()
    }

    pub fn read(&self) -> Result<ProtectedGuard<'_, A, T>, super::ProtectedMemoryError> {
        if !self.can_read() {
            return Err(super::ProtectedMemoryError::ReadAccessViolation);
        }
        Ok(ProtectedGuard { memory: self })
    }

    pub fn write(&mut self) -> Result<ProtectedGuardMut<'_, A, T>, super::ProtectedMemoryError> {
        if !self.can_write() {
            return Err(super::ProtectedMemoryError::WriteAccessViolation);
        }
        Ok(ProtectedGuardMut { memory: self })
    }

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

pub struct ProtectedGuard<'a, A: allocator::Allocator<T>, T> {
    memory: &'a ProtectedMemory<A, T>,
}

impl<'a, A: allocator::Allocator<T>, T> Deref for ProtectedGuard<'a, A, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe {
            self.memory.memory.ptr().as_ref().unwrap()      // NonNull<T>
        }
    }
}

pub struct ProtectedGuardMut<'a, A: allocator::Allocator<T>, T> {
    memory: &'a mut ProtectedMemory<A, T>,
}

impl<'a, A: allocator::Allocator<T>, T> Deref for ProtectedGuardMut<'a, A, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe {
            self.memory.memory.ptr().as_ref().unwrap()      // NonNull<T>
        }
    }
}

impl<'a, A: allocator::Allocator<T>, T> DerefMut for ProtectedGuardMut<'a, A, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            self.memory.memory.ptr().as_mut().unwrap()      // NonNull<T>
        }
    }
}
