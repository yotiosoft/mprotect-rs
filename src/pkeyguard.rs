use crate::pkey::*;
use crate::mprotect::*;
use crate::RegionGuard;
use crate::GuardRef;
use crate::GuardRefMut;
use crate::GuardError;

use std::cell::Cell;

mod access_rights;
pub use access_rights::*;

pub struct AssociatedRegion<'r, 'p, A: allocator::Allocator<T>, T, Rights>
where 
    Rights: Access,
{
    region: &'r mut RegionGuard<A, T>,
    pkey_guard: &'p PkeyGuard<T>,
    _rights: std::marker::PhantomData<Rights>,
}

impl<'r, 'p, A: allocator::Allocator<T>, T, Rights> AssociatedRegion<'r, 'p, A, T, Rights>
where
    Rights: Access,
{
    pub fn new(region: &'r mut RegionGuard<A, T>, pkey_guard: &'p PkeyGuard<T>) -> Self {
        pkey_guard.associated_count.set(pkey_guard.associated_count.get() + 1);
        AssociatedRegion { region, pkey_guard, _rights: std::marker::PhantomData }
    }

    pub fn read(&self) -> Result<GuardRef<'_, A, T>, GuardError> 
    where 
        Rights: CanRead,
    {
        self.region.read()
    }

    pub fn write(&mut self) -> Result<GuardRefMut<'_, A, T>, GuardError>
    where
        Rights: CanWrite,
    {
        self.region.write()
    }

    pub fn set_access_rights(self, access_rights: PkeyAccessRights) -> Result<AssociatedRegion<'r, 'p, A, T, Rights>, super::MprotectError> {
        self.pkey_guard.pkey.set_access_rights(access_rights)?;
        Ok(self)
    }
}

pub struct PkeyGuard<T> {
    pkey: PKey,
    default_access_rights: PkeyAccessRights,
    associated_count: Cell<usize>,
    _marker: std::marker::PhantomData<T>,
}

impl<T> PkeyGuard<T> {
    pub fn new(default_access_rights: PkeyAccessRights) -> Result<Self, super::MprotectError> {
        let pkey = PKey::new(default_access_rights)?;
        Ok(
            PkeyGuard {
                pkey,
                default_access_rights,
                associated_count: Cell::new(0),
                _marker: std::marker::PhantomData,
            }
        )
    }

    pub fn pkey(&self) -> &PKey {
        &self.pkey
    }

    pub fn associate<'r, Rights>(&self, region: &'r mut RegionGuard<impl allocator::Allocator<T>, T>) -> Result<AssociatedRegion<'r, '_, impl allocator::Allocator<T>, T, Rights>, super::MprotectError>
    where
        Rights: Access,
    {
        unsafe {
            self.pkey.associate(region.get_region(), region.access_rights())?;
        }
        Ok(AssociatedRegion::new(region, self))
    }
}
