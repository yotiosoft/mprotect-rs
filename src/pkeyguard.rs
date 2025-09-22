use crate::pkey::*;
use crate::RegionGuard;
use crate::GuardRef;
use crate::GuardRefMut;
use crate::GuardError;
use crate::allocator;

use std::cell::Cell;

mod access_rights;
pub use access_rights::permissions as PkeyPermissions;
pub use PkeyPermissions::{ ReadOnly, ReadWrite, NoAccess };

#[derive(Debug)]
pub enum PkeyGuardError {
    MprotectError(super::MprotectError),
    RegionGuardError(GuardError),
}

pub struct AssociatedRegion<'p, A: allocator::Allocator<T>, T, Rights>
where 
    Rights: access_rights::Access,
{
    region: *mut RegionGuard<A, T>,
    pkey_guard: &'p PkeyGuard<A, T>,
    access_rights: Rights,
}

impl<'r, 'p, A: allocator::Allocator<T>, T, Rights> AssociatedRegion<'p, A, T, Rights>
where
    Rights: access_rights::Access,
{
    pub fn new(region: &mut RegionGuard<A, T>, pkey_guard: &'p PkeyGuard<A, T>) -> Self {
        AssociatedRegion { 
            region, 
            pkey_guard, 
            access_rights: Rights::new(),
        }
    }

    fn sync_pkey_permissions(&self) -> Result<(), super::MprotectError> {
        if self.pkey_guard.current_access_rights.get() == self.access_rights.value() {
            return Ok(());
        }
        self.pkey_guard.pkey.set_access_rights(self.access_rights.value())?;
        self.pkey_guard.current_access_rights.set(self.access_rights.value());
        Ok(())
    }

    pub fn read(&self) -> Result<GuardRef<'_, A, T>, PkeyGuardError>
    where 
        Rights: access_rights::CanRead,
    {
        self.sync_pkey_permissions().map_err(PkeyGuardError::MprotectError)?;
        unsafe { (*self.region).read().map_err(PkeyGuardError::RegionGuardError) }
    }

    pub fn write(&self) -> Result<GuardRefMut<'_, A, T>, PkeyGuardError>
    where
        Rights: access_rights::CanWrite,
    {
        self.sync_pkey_permissions().map_err(PkeyGuardError::MprotectError)?;
        unsafe { (*self.region).write().map_err(PkeyGuardError::RegionGuardError) }
    }

    pub fn set_access_rights<NewRights: access_rights::Access>(&self) -> Result<AssociatedRegion<'p, A, T, NewRights>, super::MprotectError> 
    where
        NewRights: access_rights::Access,
    {
        self.pkey_guard.pkey.set_access_rights(NewRights::new().value())?;
        println!("New PKey access rights set to {:?}", NewRights::new().value());

        self.pkey_guard.ref_counter.set(self.pkey_guard.ref_counter.get() + 1);
        Ok(AssociatedRegion {
            region: self.region,
            pkey_guard: self.pkey_guard,
            access_rights: NewRights::new(),
        })
    }
}
impl <'r, 'p, A: allocator::Allocator<T>, T, Rights> Drop for AssociatedRegion<'p, A, T, Rights>
where 
    Rights: access_rights::Access,
{
    fn drop(&mut self) {
        // If the reference count is greater than one, it means that there are other
        // AssociatedRegion instances still using the same PKey. In this case, we do not
        // reset the PKey access rights to the previous state.
        println!("AssociatedRegion dropped, current reference count: {}", self.pkey_guard.ref_counter.get());
        if self.pkey_guard.ref_counter.get() > 1 {
            self.pkey_guard.ref_counter.set(self.pkey_guard.ref_counter.get() - 1);
            return;
        }

        self.pkey_guard.ref_counter.set(0);
        self.pkey_guard.pkey.set_access_rights(self.pkey_guard.default_access_rights).unwrap_or_else(|e| {
            panic!("Failed to reset PKey access rights: {:?}", e);
        });
        println!("Dropped AssociatedRegion, reset PKey access rights to {:?}",self.pkey_guard.default_access_rights);
    }
}

pub struct PkeyGuard<A, T> {
    pkey: PKey,
    ref_counter: Cell<u32>,
    default_access_rights: PkeyAccessRights,
    current_access_rights: Cell<PkeyAccessRights>,
    _marker: std::marker::PhantomData<(A, T)>,
}

impl<A, T> PkeyGuard<A, T> {
    pub fn new<Access: access_rights::Access>(default_access_rights: Access) -> Result<Self, super::MprotectError> {
        let pkey = PKey::new(default_access_rights.value())?;
        Ok(
            PkeyGuard {
                pkey,
                ref_counter: Cell::new(0),
                default_access_rights: default_access_rights.value(),
                current_access_rights: Cell::new(default_access_rights.value()),
                _marker: std::marker::PhantomData,
            }
        )
    }

    pub fn pkey(&self) -> &PKey {
        &self.pkey
    }

    pub fn associate<Rights>(&self, region: &mut RegionGuard<A, T>) -> Result<AssociatedRegion<'_, A, T, Rights>, super::MprotectError>
    where
        A: allocator::Allocator<T>,
        Rights: access_rights::Access,
    {
        unsafe {
            self.pkey.associate(region.get_region(), region.access_rights())?;
        }

        self.pkey.set_access_rights(Rights::new().value())?;
        self.ref_counter.set(self.ref_counter.get() + 1);
        Ok(AssociatedRegion::new(region, self))
    }
}
