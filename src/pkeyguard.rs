use crate::pkey::*;
use crate::RegionGuard;
use crate::GuardRef;
use crate::GuardRefMut;
use crate::GuardError;
use crate::allocator;

use std::cell::Cell;
use std::cell::RefCell;

mod access_rights;
pub use access_rights::permissions as PkeyPermissions;
pub use PkeyPermissions::{ ReadOnly, ReadWrite, NoAccess };

#[derive(Debug)]
pub enum PkeyGuardError {
    MprotectError(super::MprotectError),
    RegionGuardError(GuardError),
    InvalidRegionError,
}

pub struct AssociatedRegion<A: allocator::Allocator<T>, T, Rights>
where 
    Rights: access_rights::Access,
{
    region: *mut RegionGuard<A, T>,
    pkey_guard: Option<PkeyGuard<A, T>>,
    access_rights: Rights,
    generation: u32,
    popped: Cell<bool>,
}

impl<A: allocator::Allocator<T>, T, Rights> AssociatedRegion<A, T, Rights>
where
    Rights: access_rights::Access,
{
    pub fn new(region: &mut RegionGuard<A, T>, pkey_guard: PkeyGuard<A, T>) -> Self {
        let access_rights = Rights::new();
        // push new access rights to stack
        pkey_guard.push_permissions(access_rights.value());

        AssociatedRegion {
            region,
            pkey_guard: Some(pkey_guard),
            access_rights,
            generation: 0,
            popped: Cell::new(false),
        }
    }

    fn sync_pkey_permissions(&self) -> Result<(), super::MprotectError> {
        if self.pkey_guard.as_ref().unwrap().current_access_rights.get() == self.access_rights.value() {
            return Ok(());
        }
        unsafe {
            self.pkey_guard.as_ref().unwrap().pkey.set_access_rights(self.access_rights.value())?;
        }
        self.pkey_guard.as_ref().unwrap().current_access_rights.set(self.access_rights.value());
        Ok(())
    }

    pub fn read(&self) -> Result<GuardRef<'_, A, T>, PkeyGuardError>
    where 
        Rights: access_rights::CanRead,
    {
        if self.region.is_null() {
            return Err(PkeyGuardError::InvalidRegionError);
        }
        
        self.sync_pkey_permissions().map_err(PkeyGuardError::MprotectError)?;
        unsafe { (*self.region).read().map_err(PkeyGuardError::RegionGuardError) }
    }

    pub fn write(&self) -> Result<GuardRefMut<'_, A, T>, PkeyGuardError>
    where
        Rights: access_rights::CanWrite,
    {
        if self.region.is_null() {
            return Err(PkeyGuardError::InvalidRegionError);
        }

        self.sync_pkey_permissions().map_err(PkeyGuardError::MprotectError)?;
        unsafe { (*self.region).write().map_err(PkeyGuardError::RegionGuardError) }
    }

    pub fn set_access_rights<NewRights: access_rights::Access>(mut self) -> Result<AssociatedRegion<A, T, NewRights>, super::MprotectError> 
    where
        NewRights: access_rights::Access,
    {
        unsafe {
            self.pkey_guard.as_ref().unwrap().pkey.set_access_rights(NewRights::new().value())?;
        }
        println!("New PKey access rights set to {:?}", NewRights::new().value());

        self.popped.set(true);
        // pop current access rights from stack
        self.pkey_guard.as_ref().unwrap().pop_permissions();
        // push new access rights to stack
        self.pkey_guard.as_ref().unwrap().push_permissions(NewRights::new().value());

        let pkey_guard = self.pkey_guard.take().unwrap();

        Ok(AssociatedRegion {
            region: self.region,
            pkey_guard: Some(pkey_guard),
            access_rights: NewRights::new(),
            generation: self.generation + 1,
            popped: Cell::new(false),
        })
    }
}
impl <A: allocator::Allocator<T>, T, Rights> Drop for AssociatedRegion<A, T, Rights>
where 
    Rights: access_rights::Access,
{
    fn drop(&mut self) {
        if !self.popped.get() {
            // pop current access rights from stack
            self.pkey_guard.as_ref().unwrap().pop_permissions();
            self.popped.set(false);
        }
        println!("Dropped AssociatedRegion, reset PKey access rights to {:?}", self.pkey_guard.as_ref().unwrap().current_access_rights.get());
    }
}

pub struct PkeyGuard<A, T> {
    pkey: PKey,
    current_access_rights: Cell<PkeyAccessRights>,
    permissions_stack: RefCell<Vec<PkeyAccessRights>>,
    _marker: std::marker::PhantomData<(A, T)>,
}

impl<A, T> PkeyGuard<A, T> {
    pub fn new<Access: access_rights::Access>(default_access_rights: Access) -> Result<Self, super::MprotectError> {
        let pkey = unsafe {
            PKey::new(default_access_rights.value())?
        };
        Ok(
            PkeyGuard {
                pkey,
                current_access_rights: Cell::new(default_access_rights.value()),
                permissions_stack: RefCell::new(vec![default_access_rights.value()]),
                _marker: std::marker::PhantomData,
            }
        )
    }

    fn pop_permissions(&self) -> Option<PkeyAccessRights> {
        let popped = self.permissions_stack.take().pop();

        println!("[popped permissions: {:?}]", popped);
        if let Some(&top) = self.permissions_stack.take().last() {
            println!("[Set pkey access rights from {:?} to {:?}]", self.current_access_rights.get(), top);
            unsafe {
                self.pkey.set_access_rights(top).unwrap();
            }
            self.current_access_rights.set(top);
        }

        popped
    }

    fn push_permissions(&self, rights: PkeyAccessRights) {
        self.permissions_stack.borrow_mut().push(rights);

        println!("[pushed permissions: {:?}]", rights);
        println!("[Set pkey access rights from {:?} to {:?}]", self.current_access_rights.get(), rights);
        unsafe {
            self.pkey.set_access_rights(rights).unwrap();
        }
        self.current_access_rights.set(rights);
    }

    pub fn pkey(&self) -> &PKey {
        &self.pkey
    }

    pub fn associate<Rights>(self, region: &mut RegionGuard<A, T>) -> Result<AssociatedRegion<A, T, Rights>, super::MprotectError>
    where
        A: allocator::Allocator<T>,
        Rights: access_rights::Access,
    {
        unsafe {
            self.pkey.associate(region.get_region(), region.access_rights())?;
            self.pkey.set_access_rights(Rights::new().value())?;
        }
        Ok(AssociatedRegion::new(region, self))
    }
}
