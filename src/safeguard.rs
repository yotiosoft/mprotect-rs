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
    memory: UnsafeProtectedRegion<A, T>,
    original_access_rights: AccessRights,
}

impl<A: allocator::Allocator<T>, T> GuardedProtectedMemory<A, T> {
    pub fn new(memory: UnsafeProtectedRegion<A, T>, default_access_rights: AccessRights, new_access_rights: AccessRights) -> Result<Self, MprotectError> {
        let original_access_rights = default_access_rights;
        memory.set_access(new_access_rights)?;
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
}

impl<A: allocator::Allocator<T>, T> Drop for GuardedProtectedMemory<A, T> {
    fn drop(&mut self) {
        let _ = self.memory.set_access(self.original_access_rights);
    }
}
