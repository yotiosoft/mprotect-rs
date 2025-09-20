use crate::pkey::*;

use crate::mprotect::*;
use crate::RegionGuard;
use crate::GuardRef;
use crate::GuardRefMut;
use crate::GuardError;

pub struct AssociatedRegionRef<'r, A: allocator::Allocator<T>, T> {
    region: &'r RegionGuard<A, T>,
    pkey: PKey,
}
impl<'r, A: allocator::Allocator<T>, T> AssociatedRegionRef<'r, A, T> {
    pub fn new(region: &'r RegionGuard<A, T>, pkey: &PKey) -> Self {
        AssociatedRegionRef { region, pkey: pkey.clone() }
    }

    pub fn read(&self) -> Result<GuardRef<'_, A, T>, GuardError> {
        self.region.read()
    }

    pub fn deref<R: ReadAllowedTrait>(&self, access_rights: R) -> Result<GuardRef<'_, A, T>, GuardError> {
        self.region.deref(access_rights)
    }
}
impl<'r, A: allocator::Allocator<T>, T> Drop for AssociatedRegionRef<'r, A, T> {
    fn drop(&mut self) {
        unsafe {
            self.pkey.disassociate(self.region.get_region(), self.region.access_rights()).expect("Failed to disassociate pkey from region");
        }
    }
}

pub struct AssociatedRegionRefMut<'a, A: allocator::Allocator<T>, T> {
    region: &'a mut RegionGuard<A, T>,
    pkey_guard: PkeyGuardMutRef<'a>,
}

impl<'a, A: allocator::Allocator<T>, T> AssociatedRegionRefMut<'a, A, T> {
    pub fn new(region: &'a mut RegionGuard<A, T>, pkey_guard: PkeyGuardMutRef<'a>) -> Self {
        AssociatedRegionRefMut { region, pkey_guard }
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

impl<'a, A: allocator::Allocator<T>, T> Drop for AssociatedRegionRefMut<'a, A, T> {
    fn drop(&mut self) {
        unsafe {
            self.pkey_guard.pkey_guard.pkey.disassociate(self.region.get_region(), self.region.access_rights()).expect("Failed to disassociate pkey from region");
        }
    }
}

pub struct PkeyGuardRef<'r> {
    pkey_guard: &'r PkeyGuard,
}
impl<'r> PkeyGuardRef<'r> {
    pub fn new(pkey_guard: &'r PkeyGuard) -> Self {
        PkeyGuardRef { pkey_guard }
    }

    pub fn associate_region_deref<A: allocator::Allocator<u32>>(&self, region: &'r RegionGuard<A, u32>) -> Result<AssociatedRegionRef<'r, A, u32>, super::MprotectError> {
        unsafe {
            self.pkey_guard.pkey.associate(region.get_region(), region.access_rights())?;
        }
        Ok(AssociatedRegionRef::new(region, &self.pkey_guard.pkey))
    }
}
impl<'r> Drop for PkeyGuardRef<'r> {
    fn drop(&mut self) {
        println!("Resetting pkey {} access rights to default {:?}", self.pkey_guard.pkey.key(), self.pkey_guard.default_access_rights);
        self.pkey_guard.pkey.set_access_rights(self.pkey_guard.default_access_rights).expect("Failed to reset pkey access rights");
    }
}

pub struct PkeyGuardMutRef<'a> {
    pkey_guard: &'a PkeyGuard,
}
impl<'a> PkeyGuardMutRef<'a> {
    pub fn new(pkey_guard: &'a PkeyGuard) -> Self {
        PkeyGuardMutRef { pkey_guard }
    }

    pub fn associate_region_deref<A: allocator::Allocator<u32>>(&self, region: &'a RegionGuard<A, u32>) -> Result<AssociatedRegionRef<'a, A, u32>, super::MprotectError> {
        unsafe {
            self.pkey_guard.pkey.associate(region.get_region(), region.access_rights())?;
        }
        Ok(AssociatedRegionRef::new(region, &self.pkey_guard.pkey))
    }

    pub fn associate_region_deref_mut<'assoc, A: allocator::Allocator<u32>>(&'a mut self, region: &'assoc mut RegionGuard<A, u32>) -> Result<AssociatedRegionRefMut<'assoc, A, u32>, super::MprotectError> 
    where 'a: 'assoc
    {
        unsafe {
            self.pkey_guard.pkey.associate(region.get_region(), region.access_rights())?;
        }
        Ok(AssociatedRegionRefMut::new(region, PkeyGuardMutRef::new(self.pkey_guard)))
    }
}
impl<'r> Drop for PkeyGuardMutRef<'r> {
    fn drop(&mut self) {
        println!("Resetting pkey {} access rights to default {:?}", self.pkey_guard.pkey.key(), self.pkey_guard.default_access_rights);
        self.pkey_guard.pkey.set_access_rights(self.pkey_guard.default_access_rights).expect("Failed to reset pkey access rights");
    }
}

pub struct PkeyGuard {
    pkey: PKey,
    default_access_rights: PkeyAccessRights,
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

    pub fn deref<'p>(&'p self, access_rights: PkeyAccessRights) -> Result<PkeyGuardRef<'p>, super::MprotectError> {
        self.pkey.set_access_rights(access_rights)?;
        Ok(PkeyGuardRef::new(self))
    }

    pub fn deref_mut<'p>(&'p self, access_rights: PkeyAccessRights) -> Result<PkeyGuardMutRef<'p>, super::MprotectError> {
        self.pkey.set_access_rights(access_rights)?;
        Ok(PkeyGuardMutRef::new(self))
    }
}
