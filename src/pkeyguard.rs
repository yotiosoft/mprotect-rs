use crate::pkey::*;

use crate::mprotect::*;
use crate::RegionGuard;
use crate::GuardRef;
use crate::GuardRefMut;
use crate::GuardError;

pub struct PkeyGuard {
    pkey: PKey,
    default_access_rights: PkeyAccessRights,
}

pub struct AssociatedRegionRef<'a, A: allocator::Allocator<T>, T> {
    region: &'a RegionGuard<A, T>,
    pkey_id: u32,
}
impl<'a, A: allocator::Allocator<T>, T> AssociatedRegionRef<'a, A, T> {
    pub fn new(region: &'a RegionGuard<A, T>, pkey_id: u32) -> Self {
        AssociatedRegionRef { region, pkey_id }
    }

    pub fn read(&self) -> Result<GuardRef<'_, A, T>, GuardError> {
        self.region.read()
    }

    pub fn deref<R: ReadAllowedTrait>(&self, access_rights: R) -> Result<GuardRef<'_, A, T>, GuardError> {
        self.region.deref(access_rights)
    }
}

pub struct AssociatedRegionRefMut<'a, A: allocator::Allocator<T>, T> {
    region: &'a mut RegionGuard<A, T>,
    pkey_id: u32,
}

impl<'a, A: allocator::Allocator<T>, T> AssociatedRegionRefMut<'a, A, T> {
    pub fn new(region: &'a mut RegionGuard<A, T>, pkey_id: u32) -> Self {
        AssociatedRegionRefMut { region, pkey_id }
    }

    pub fn read(&self) -> Result<GuardRef<'_, A, T>, GuardError> {
        self.region.read()
    }

    pub fn write(&mut self) -> Result<GuardRefMut<'_, A, T>, GuardError> {
        self.region.write()
    }

    pub fn deref<R: ReadAllowedTrait>(&self, access_rights: R) -> Result<GuardRef<'_, A, T>, GuardError> {
        self.region.deref(access_rights)
    }

    pub fn deref_mut<R: WriteAllowedTrait>(&mut self, access_rights: R) -> Result<GuardRefMut<'_, A, T>, GuardError> {
        self.region.deref_mut(access_rights)
    }
}

impl PkeyGuard {
    pub fn new(default_access_rights: PkeyAccessRights) -> Result<Self, super::MprotectError> {
        let pkey = PKey::new(default_access_rights)?;
        Ok(
            PkeyGuard {
                pkey,
                default_access_rights,
            }
        )
    }

    pub fn pkey(&self) -> &PKey {
        &self.pkey
    }

    pub fn associate_region_deref<'a, A: allocator::Allocator<u32>>(&self, region: &'a RegionGuard<A, u32>) -> AssociatedRegionRef<'a, A, u32> {
        AssociatedRegionRef::new(region, self.pkey.key())
    }

    pub fn associate_region_deref_mut<'a, A: allocator::Allocator<u32>>(&self, region: &'a mut RegionGuard<A, u32>) -> AssociatedRegionRefMut<'a, A, u32> {
        AssociatedRegionRefMut::new(region, self.pkey.key())
    }
}
