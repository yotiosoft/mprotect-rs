use crate::pkey::*;
use crate::RegionGuard;
use crate::GuardRef;
use crate::GuardRefMut;
use crate::GuardError;
use crate::allocator;

use std::rc::Rc;
use std::cell::Cell;

mod access_rights;
pub use access_rights::permissions as PkeyPermissions;
pub use PkeyPermissions::{ ReadOnly, ReadWrite, NoAccess };

pub struct AssociatedRegion<'p, A: allocator::Allocator<T>, T, Rights>
where 
    Rights: access_rights::Access,
{
    region: *mut RegionGuard<A, T>,
    pkey_guard: &'p PkeyGuard<A, T>,
    permission: Rights,
    generation: Rc<Cell<u32>>,
}

impl<'r, 'p, A: allocator::Allocator<T>, T, Rights> AssociatedRegion<'p, A, T, Rights>
where
    Rights: access_rights::Access,
{
    pub fn new(region: &mut RegionGuard<A, T>, pkey_guard: &'p PkeyGuard<A, T>) -> Self {
        pkey_guard.associated_count.set(pkey_guard.associated_count.get() + 1);
        AssociatedRegion { 
            region, 
            pkey_guard, 
            permission: Rights::new(),
            generation: Rc::new(Cell::new(pkey_guard.generation.get())),
        }
    }

    pub fn read(&self) -> Result<GuardRef<'_, A, T>, GuardError> 
    where 
        Rights: access_rights::CanRead,
    {
        unsafe { (*self.region).read() }
    }

    pub fn write(&mut self) -> Result<GuardRefMut<'_, A, T>, GuardError>
    where
        Rights: access_rights::CanWrite,
    {
        unsafe { (*self.region).write() }
    }

    pub fn set_access_rights<NewRights: access_rights::Access>(self) -> Result<AssociatedRegion<'p, A, T, NewRights>, super::MprotectError> 
    where
        NewRights: access_rights::Access,
    {
        self.pkey_guard.pkey.set_access_rights(NewRights::new().value())?;

        println!("New PKey access rights set to {:?}", NewRights::new().value());

        let gen = self.pkey_guard.generation.get() + 1;
        self.pkey_guard.generation.set(gen);

        println!("New generation: {}", gen);

        Ok(AssociatedRegion {
            region: self.region,
            pkey_guard: self.pkey_guard,
            permission: NewRights::new(),
            generation: Rc::new(Cell::new(gen)),
        })
    }
}
impl <'r, 'p, A: allocator::Allocator<T>, T, Rights> Drop for AssociatedRegion<'p, A, T, Rights>
where 
    Rights: access_rights::Access,
{
    fn drop(&mut self) {
        // If the generation of the PKeyGuard has changed, it means that the PKey access rights
        // have already been changed by another AssociatedRegion. In this case, we do not
        // reset the PKey access rights to the previous state.
        println!("AssociatedRegion dropped, current generation: {}, pkey_guard generation: {}", self.generation.get(), self.pkey_guard.generation.get());
        if self.generation.get() < self.pkey_guard.generation.get() {
            return;
        }

        self.pkey_guard.pkey.set_access_rights(self.pkey_guard.default_access_rights).unwrap_or_else(|e| {
            panic!("Failed to reset PKey access rights: {:?}", e);
        });
        println!("Dropped AssociatedRegion, reset PKey access rights to {:?}",self.pkey_guard.default_access_rights);

        let count = self.pkey_guard.associated_count.get();
        if count > 0 {
            self.pkey_guard.associated_count.set(count - 1);
        }
    }
}

pub struct PkeyGuard<A, T> {
    pkey: PKey,
    associated_count: Cell<usize>,
    generation: Rc<Cell<u32>>,
    default_access_rights: PkeyAccessRights,
    _marker: std::marker::PhantomData<(A, T)>,
}

impl<A, T> PkeyGuard<A, T> {
    pub fn new<Access: access_rights::Access>(default_access_rights: Access) -> Result<Self, super::MprotectError> {
        let pkey = PKey::new(default_access_rights.value())?;
        Ok(
            PkeyGuard {
                pkey,
                associated_count: Cell::new(0),
                generation: Rc::new(Cell::new(0)),
                default_access_rights: default_access_rights.value(),
                _marker: std::marker::PhantomData,
            }
        )
    }

    pub fn pkey(&self) -> &PKey {
        &self.pkey
    }

    pub fn associate<Rights>(&mut self, region: &mut RegionGuard<A, T>) -> Result<AssociatedRegion<'_, A, T, Rights>, super::MprotectError>
    where
        A: allocator::Allocator<T>,
        Rights: access_rights::Access,
    {
        unsafe {
            self.pkey.associate(region.get_region(), region.access_rights())?;
        }

        self.pkey.set_access_rights(Rights::new().value())?;
        
        println!("Current generation: {}", self.generation.get());
        Ok(AssociatedRegion::new(region, self))
    }
}
