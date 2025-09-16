pub use crate::mprotect::*;
pub use crate::safemem::*;
pub use crate::MprotectError;

pub struct GuardedPKey {
    pkey: PKey,
    original_access_rights: PkeyAccessRights,
}

impl GuardedPKey {
    pub fn new(pkey: &PKey, new_access_rights: PkeyAccessRights) -> Result<Self, MprotectError> {
        let original_access_rights = pkey.get_access_rights();
        pkey.set_access_rights(new_access_rights)?;
        Ok(
            GuardedPKey {
                pkey: pkey.clone(),
                original_access_rights,
            }
        )
    }
}

impl Drop for GuardedPKey {
    fn drop(&mut self) {
        let _ = self.pkey.set_access_rights(self.original_access_rights);
    }
}

pub struct GuardedProtectedMemory<A: allocator::Allocator<T>, T> {
    memory: UnsafeProtectedMemory<A, T>,
    original_access_rights: AccessRights,
}

impl<A: allocator::Allocator<T>, T> GuardedProtectedMemory<A, T> {
    pub fn new(memory: UnsafeProtectedMemory<A, T>, new_access_rights: AccessRights) -> Result<Self, MprotectError> {
        let original_access_rights = memory.region_access_rights();
        memory.mprotect(new_access_rights)?;
        Ok(
            GuardedProtectedMemory {
                memory,
                original_access_rights,
            }
        )
    }

    pub fn as_mut(&mut self) -> &mut T {
        self.memory.as_mut()
    }

    pub fn region_access_rights(&self) -> AccessRights {
        self.memory.region_access_rights()
    }
}

impl<A: allocator::Allocator<T>, T> Drop for GuardedProtectedMemory<A, T> {
    fn drop(&mut self) {
        let _ = self.memory.mprotect(self.original_access_rights);
    }
}
