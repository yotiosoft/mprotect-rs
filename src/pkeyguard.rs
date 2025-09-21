use crate::pkey::*;
use crate::mprotect::*;
use crate::RegionGuard;
use crate::GuardRef;
use crate::GuardRefMut;
use crate::GuardError;
use crate::allocator;

use std::cell::Cell;

mod access_rights;
pub use access_rights::permissions as PkeyPermissions;
pub use PkeyPermissions::{ ReadOnly, ReadWrite, NoAccess };

pub struct AssociatedRegion<'r, 'p, A: allocator::Allocator<T>, T, Rights>
where 
    Rights: access_rights::Access,
{
    region: &'r mut RegionGuard<A, T>,
    pkey_guard: &'p PkeyGuard<A, T>,
    _rights: std::marker::PhantomData<Rights>,
}

impl<'r, 'p, A: allocator::Allocator<T>, T, Rights> AssociatedRegion<'r, 'p, A, T, Rights>
where
    Rights: access_rights::Access,
{
    pub fn new(region: &'r mut RegionGuard<A, T>, pkey_guard: &'p PkeyGuard<A, T>) -> Self {
        pkey_guard.associated_count.set(pkey_guard.associated_count.get() + 1);
        AssociatedRegion { region, pkey_guard, _rights: std::marker::PhantomData }
    }

    pub fn read(&self) -> Result<GuardRef<'_, A, T>, GuardError> 
    where 
        Rights: access_rights::CanRead,
    {
        self.region.read()
    }

    pub fn write(&mut self) -> Result<GuardRefMut<'_, A, T>, GuardError>
    where
        Rights: access_rights::CanWrite,
    {
        self.region.write()
    }

    pub fn set_access_rights<NewRights: access_rights::Access>(self) -> Result<AssociatedRegion<'r, 'p, A, T, NewRights>, super::MprotectError> 
    where
        NewRights: access_rights::Access,
    {
        self.pkey_guard.pkey.set_access_rights(NewRights::new().value())?;
        Ok(AssociatedRegion {
            region: self.region,
            pkey_guard: self.pkey_guard,
            _rights: std::marker::PhantomData,
        })
    }
}

pub struct PkeyGuard<A, T> {
    pkey: PKey,
    default_access_rights: PkeyAccessRights,
    associated_count: Cell<usize>,
    _marker: std::marker::PhantomData<(A, T)>,
}

impl<A, T> PkeyGuard<A, T> {
    pub fn new<Access: access_rights::Access>(default_access_rights: Access) -> Result<Self, super::MprotectError> {
        let pkey = PKey::new(default_access_rights.value())?;
        Ok(
            PkeyGuard {
                pkey,
                default_access_rights: default_access_rights.value(),
                associated_count: Cell::new(0),
                _marker: std::marker::PhantomData,
            }
        )
    }

    pub fn pkey(&self) -> &PKey {
        &self.pkey
    }

    pub fn associate<'r, Rights>(&self, region: &'r mut RegionGuard<A, T>) -> Result<AssociatedRegion<'r, '_, A, T, Rights>, super::MprotectError>
    where
        A: allocator::Allocator<T>,
        Rights: access_rights::Access,
    {
        unsafe {
            self.pkey.associate(region.get_region(), region.access_rights())?;
        }
        self.pkey.set_access_rights(Rights::new().value())?;
        Ok(AssociatedRegion::new(region, self))
    }
}
