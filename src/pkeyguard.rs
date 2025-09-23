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

pub struct AssociatedRegion<'p, A: allocator::Allocator<T>, T, Rights>
where 
    Rights: access_rights::Access,
{
    region: *mut RegionGuard<A, T>,
    pkey_guard: &'p PkeyGuard<A, T>,
    access_rights: Rights,
    popped: Cell<bool>,
}

impl<'p, A: allocator::Allocator<T>, T, Rights> AssociatedRegion<'p, A, T, Rights>
where
    Rights: access_rights::Access,
{
    pub fn new(region: &mut RegionGuard<A, T>, pkey_guard: &'p PkeyGuard<A, T>) -> Self {
        let access_rights = Rights::new();
        // push new access rights to stack
        pkey_guard.push_permissions(access_rights.value());

        AssociatedRegion {
            region,
            pkey_guard,
            access_rights,
            popped: Cell::new(false),
        }
    }

    fn sync_pkey_permissions(&self) -> Result<(), super::MprotectError> {
        if self.pkey_guard.current_access_rights.get() == self.access_rights.value() {
            return Ok(());
        }
        unsafe {
            self.pkey_guard.pkey.set_access_rights(self.access_rights.value())?;
        }
        self.pkey_guard.current_access_rights.set(self.access_rights.value());
        Ok(())
    }

    pub fn ref_guard(&self) -> Result<GuardRef<'p, A, T>, PkeyGuardError>
    where 
        Rights: access_rights::CanRead,
    {
        if self.region.is_null() {
            return Err(PkeyGuardError::InvalidRegionError);
        }
        
        self.sync_pkey_permissions().map_err(PkeyGuardError::MprotectError)?;
        unsafe { (*self.region).read().map_err(PkeyGuardError::RegionGuardError) }
    }

    pub fn mut_ref_guard(&self) -> Result<GuardRefMut<'p, A, T>, PkeyGuardError>
    where
        Rights: access_rights::CanWrite,
    {
        if self.region.is_null() {
            return Err(PkeyGuardError::InvalidRegionError);
        }

        self.sync_pkey_permissions().map_err(PkeyGuardError::MprotectError)?;
        unsafe { (*self.region).write().map_err(PkeyGuardError::RegionGuardError) }
    }
}
impl<'p, A: allocator::Allocator<T>, T, Rights> Drop for AssociatedRegion<'p, A, T, Rights>
where
    Rights: access_rights::Access,
{
    fn drop(&mut self) {
        if !self.popped.get() {
            // pop current access rights from stack
            self.pkey_guard.pop_permissions();
            self.popped.set(false);
        }
        //println!("Dropped AssociatedRegion, reset PKey access rights to {:?}", self.pkey_guard.current_access_rights.get());
    }
}

pub struct AssociatedRegionHandler<'p, A: allocator::Allocator<T>, T, Rights>
where 
    Rights: access_rights::Access,
{
    associated_region: AssociatedRegion<'p, A, T, Rights>,
    pkey_guard: &'p PkeyGuard<A, T>,
}

impl<'a, 'p, A: allocator::Allocator<T>, T, Rights> AssociatedRegionHandler<'p, A, T, Rights>
where 
    Rights: access_rights::Access,
{
    pub fn new(region: &mut RegionGuard<A, T>, pkey_guard: &'p PkeyGuard<A, T>) -> Self {
        AssociatedRegionHandler {
            associated_region: AssociatedRegion::new(region, pkey_guard),
            pkey_guard,
        }
    }

    pub fn set_access_rights<NewRights: access_rights::Access>(&'a mut self) -> Result<AssociatedRegion<'a, A, T, NewRights>, super::MprotectError> 
    where
        NewRights: access_rights::Access,
    {
        unsafe {
            self.pkey_guard.pkey.set_access_rights(NewRights::new().value())?;
        }
        println!("New PKey access rights set to {:?}", NewRights::new().value());

        self.associated_region.popped.set(true);
        self.pkey_guard.push_permissions(NewRights::new().value());

        Ok(AssociatedRegion {
            region: self.associated_region.region,
            pkey_guard: self.pkey_guard,
            access_rights: NewRights::new(),
            popped: Cell::new(false),
        })
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
        let popped = self.permissions_stack.borrow_mut().pop();

        //println!("[popped permissions: {:?}]", popped);

        if let Some(top) = self.permissions_stack.borrow().last() {
            let top = *top;
            //println!("[Set pkey access rights from {:?} to {:?}]", self.current_access_rights.get(), top);
            unsafe {
                self.pkey.set_access_rights(top).expect("Failed to set pkey access rights");
            }
            self.current_access_rights.set(top);
        }

        popped
    }

    fn push_permissions(&self, rights: PkeyAccessRights) {
        self.permissions_stack.borrow_mut().push(rights);

        //println!("[pushed permissions: {:?}]", rights);
        //println!("[Set pkey access rights from {:?} to {:?}]", self.current_access_rights.get(), rights);
        unsafe {
            self.pkey.set_access_rights(rights).expect("Failed to set pkey access rights");
        }
        self.current_access_rights.set(rights);
    }

    pub fn pkey(&self) -> &PKey {
        &self.pkey
    }

    pub fn associate<Rights>(&self, region: &mut RegionGuard<A, T>) -> Result<AssociatedRegionHandler<'_, A, T, Rights>, super::MprotectError>
    where
        A: allocator::Allocator<T>,
        Rights: access_rights::Access,
    {
        unsafe {
            self.pkey.associate(region.get_region(), region.access_rights())?;
            self.pkey.set_access_rights(Rights::new().value())?;
        }
        Ok(AssociatedRegionHandler::new(region, self))
    }
}
