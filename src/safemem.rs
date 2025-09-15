pub use crate::mprotect::*;
pub use crate::pkey::*;

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

    fn can_write(&self) -> bool {
        let mut can_write = true;
        if let Some(pkey) = &self.pkey {
            if pkey.access_rights() == PkeyAccessRights::DisableWrite || pkey.access_rights() == PkeyAccessRights::DisableAccess {
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
            if pkey.access_rights() == PkeyAccessRights::DisableAccess {
                can_read = false;
            }
        }
        if self.region_access_rights() == AccessRights::None || self.region_access_rights() == AccessRights::Exec || self.region_access_rights() == AccessRights::Write || self.region_access_rights() == AccessRights::WriteExec {
            can_read = false;
        }

        can_read
    }

    fn can_execute(&self) -> bool {
        let mut can_execute = true;
        if let Some(pkey) = &self.pkey {
            if pkey.access_rights() == PkeyAccessRights::DisableAccess {
                can_execute = false;
            }
        }
        if self.region_access_rights() == AccessRights::None || self.region_access_rights() == AccessRights::Read || self.region_access_rights() == AccessRights::Write || self.region_access_rights() == AccessRights::ReadWrite {
            can_execute = false;
        }

        can_execute
    }
}
