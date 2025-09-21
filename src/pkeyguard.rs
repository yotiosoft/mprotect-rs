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

pub struct Unassociated;
pub struct Associated<Rights>(std::marker::PhantomData<Rights>);

pub struct AssociatedRegion<'r, A: allocator::Allocator<T>, T, Rights>
where 
    Rights: access_rights::Access,
{
    region: &'r mut RegionGuard<A, T>,
    pkey_guard: PkeyGuard<Associated<Rights>>,
    _rights: std::marker::PhantomData<Rights>,
}

impl<'r, A: allocator::Allocator<T>, T, Rights> AssociatedRegion<'r, A, T, Rights>
where
    Rights: access_rights::Access,
{
    pub fn new(region: &'r mut RegionGuard<A, T>, pkey_guard: PkeyGuard<Associated<Rights>>) -> Self {
        pkey_guard.associated_count.set(pkey_guard.associated_count.get() + 1);
        Self {
            region,
            pkey_guard: PkeyGuard {
                _state: std::marker::PhantomData::<Associated<Rights>>,
                ..pkey_guard
            },
            _rights: std::marker::PhantomData,
        }
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

    pub fn set_access_rights<NewRights: access_rights::Access>(self) -> Result<AssociatedRegion<'r, A, T, NewRights>, super::MprotectError> 
    where
        NewRights: access_rights::Access,
    {
        self.pkey_guard.pkey.set_access_rights(NewRights::new().value())?;
        Ok(AssociatedRegion {
            region: self.region,
            pkey_guard: PkeyGuard {
                pkey: self.pkey_guard.pkey.clone(),
                default_access_rights: self.pkey_guard.default_access_rights,
                associated_count: Cell::new(self.pkey_guard.associated_count.get()),
                _state: std::marker::PhantomData::<Associated<NewRights>>,
            },
            _rights: std::marker::PhantomData,
        })
    }
}

pub struct PkeyGuard<State> {
    pkey: PKey,
    default_access_rights: PkeyAccessRights,
    associated_count: Cell<usize>,
    _state: std::marker::PhantomData<State>,
}

impl<Unassociated> PkeyGuard<Unassociated> {
    pub fn new<Access: access_rights::Access>(default_access_rights: Access) -> Result<Self, super::MprotectError> {
        let pkey = PKey::new(default_access_rights.value())?;
        Ok(
            PkeyGuard {
                pkey,
                default_access_rights: default_access_rights.value(),
                associated_count: Cell::new(0),
                _state: std::marker::PhantomData,
            }
        )
    }

    pub fn pkey(&self) -> &PKey {
        &self.pkey
    }

    pub fn associate<'r, A: allocator::Allocator<T>, T, Rights>(&self, region: &'r mut RegionGuard<A, T>) -> Result<AssociatedRegion<'r, A, T, Rights>, super::MprotectError>
    where
        A: allocator::Allocator<T>,
        Rights: access_rights::Access,
    {
        unsafe {
            self.pkey.associate(region.get_region(), region.access_rights())?;
        }
        self.pkey.set_access_rights(Rights::new().value())?;

        Ok(AssociatedRegion {
            region,
            pkey_guard: PkeyGuard {
                pkey: self.pkey.clone(),
                default_access_rights: self.default_access_rights,
                associated_count: Cell::new(1),
                _state: std::marker::PhantomData::<Associated<Rights>>,
            },
            _rights: std::marker::PhantomData,
        })
    }
}
