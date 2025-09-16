pub use crate::mprotect::*;
pub use crate::pkey::*;

use std::ops::{Deref, DerefMut};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeProtectedMemoryError {
    ReadAccessViolation,
    WriteAccessViolation,
    ExecuteAccessViolation,
}
impl std::fmt::Display for SafeProtectedMemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SafeProtectedMemoryError::ReadAccessViolation => write!(f, "read access violation"),
            SafeProtectedMemoryError::WriteAccessViolation => write!(f, "write access violation"),
            SafeProtectedMemoryError::ExecuteAccessViolation => write!(f, "execute access violation"),
        }
    }
}

pub struct SafeProtectedMemory<A: allocator::Allocator<T>, T> {
    memory: ProtectedMemory<A, T>,
    pkey: Option<ProtectionKey>,
}

impl<A: allocator::Allocator<T>, T> SafeProtectedMemory<A, T> {
    pub fn new(access_rights: AccessRights) -> Result<Self, super::MprotectError> {
        let memory = ProtectedMemory::without_pkey(access_rights)?;
        Ok(Self { memory, pkey: None })
    }

    pub fn new_with_pkey(access_rights: AccessRights, pkey: &ProtectionKey) -> Result<Self, super::MprotectError> {
        let memory = ProtectedMemory::with_pkey(access_rights, pkey)?;
        Ok(Self { memory, pkey: Some(pkey.clone()) })
    }

    pub fn mprotect(&self, access_rights: AccessRights) -> Result<(), super::MprotectError> {
        self.memory.mprotect(access_rights)
    }

    pub fn as_mut(&mut self) -> &mut T {
        self.memory.as_mut()
    }

    pub fn pkey(&self) -> Option<&ProtectionKey> {
        self.pkey.as_ref()
    }

    pub fn region_access_rights(&self) -> AccessRights {
        self.memory.region_access_rights()
    }

    pub fn read(&self) -> Result<ProtectedGuard<'_, A, T>, super::SafeProtectedMemoryError> {
        if !self.can_read() {
            return Err(super::SafeProtectedMemoryError::ReadAccessViolation);
        }
        Ok(ProtectedGuard { memory: self })
    }

    pub fn write(&mut self) -> Result<ProtectedGuardMut<'_, A, T>, super::SafeProtectedMemoryError> {
        if !self.can_write() {
            return Err(super::SafeProtectedMemoryError::WriteAccessViolation);
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
    memory: &'a SafeProtectedMemory<A, T>,
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
    memory: &'a mut SafeProtectedMemory<A, T>,
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
