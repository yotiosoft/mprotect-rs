use crate::pkey::*;

use crate::mprotect::*;
use crate::RegionGuard;
use crate::GuardRef;
use crate::GuardRefMut;
use crate::GuardError;

pub struct AssociatedRegionRef<'r, 'p, A: allocator::Allocator<T>, T> {
    region: &'r RegionGuard<A, T>,
    pkey: &'p PKey,
}
impl<'r, 'p, A: allocator::Allocator<T>, T> AssociatedRegionRef<'r, 'p, A, T> {
    pub fn new(region: &'r RegionGuard<A, T>, pkey: &'p PKey) -> Self {
        AssociatedRegionRef { region, pkey }
    }

    pub fn read(&self) -> Result<GuardRef<'_, A, T>, GuardError> {
        self.region.read()
    }

    pub fn deref<R: ReadAllowedTrait>(&self, access_rights: R) -> Result<GuardRef<'_, A, T>, GuardError> {
        self.region.deref(access_rights)
    }
}
impl<'r, 'p, A: allocator::Allocator<T>, T> Drop for AssociatedRegionRef<'r, 'p, A, T> {
    fn drop(&mut self) {
        unsafe {
            self.pkey.disassociate(self.region.get_region(), self.region.access_rights()).expect("Failed to disassociate pkey from region");
        }
    }
}

pub struct AssociatedRegionRefMut<'r, A: allocator::Allocator<T>, T> {
    region: &'r mut RegionGuard<A, T>,
    pkey: PKey,
}

impl<'r, A: allocator::Allocator<T>, T> AssociatedRegionRefMut<'r, A, T> {
    pub fn new(region: &'r mut RegionGuard<A, T>, pkey: &PKey) -> Self {
        AssociatedRegionRefMut { region, pkey: pkey.clone() }
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

impl<'r, 'p, A: allocator::Allocator<T>, T> Drop for AssociatedRegionRefMut<'r, A, T> {
    fn drop(&mut self) {
        unsafe {
            self.pkey.disassociate(self.region.get_region(), self.region.access_rights()).expect("Failed to disassociate pkey from region");
        }
    }
}

pub struct PkeyGuardRef<'p> {
    pkey_guard: &'p PkeyGuard,
}
impl<'p> PkeyGuardRef<'p> {
    pub fn new(pkey_guard: &'p PkeyGuard) -> Self {
        PkeyGuardRef { pkey_guard }
    }

    pub fn associate_region_deref<'r, A: allocator::Allocator<u32>>(&self, region: &'r RegionGuard<A, u32>) -> Result<AssociatedRegionRef<'r, 'p, A, u32>, super::MprotectError> {
        unsafe {
            self.pkey_guard.pkey.associate(region.get_region(), region.access_rights())?;
        }
        Ok(AssociatedRegionRef::new(region, &self.pkey_guard.pkey))
    }
}
impl<'p> Drop for PkeyGuardRef<'p> {
    fn drop(&mut self) {
        println!("Resetting pkey {} access rights to default {:?}", self.pkey_guard.pkey.key(), self.pkey_guard.default_access_rights);
        self.pkey_guard.pkey.set_access_rights(self.pkey_guard.default_access_rights).expect("Failed to reset pkey access rights");
    }
}

pub struct PkeyGuardRefMut<'p> {
    pkey_guard: &'p PkeyGuard,
}
impl<'p> PkeyGuardRefMut<'p> {
    pub fn new(pkey_guard: &'p PkeyGuard) -> Self {
        PkeyGuardRefMut { pkey_guard }
    }

    pub fn associate_region_deref<'r, A: allocator::Allocator<u32>>(&self, region: &'r RegionGuard<A, u32>) -> Result<AssociatedRegionRef<'r, 'p, A, u32>, super::MprotectError> {
        unsafe {
            self.pkey_guard.pkey.associate(region.get_region(), region.access_rights())?;
        }
        Ok(AssociatedRegionRef::new(region, &self.pkey_guard.pkey))
    }

    pub fn associate_region_deref_mut<'r, A: allocator::Allocator<u32>>(&mut self, region: &'r mut RegionGuard<A, u32>) -> Result<AssociatedRegionRefMut<'r, A, u32>, super::MprotectError> {
        unsafe {
            self.pkey_guard.pkey.associate(region.get_region(), region.access_rights())?;
        }
        Ok(AssociatedRegionRefMut::new(region, &self.pkey_guard.pkey))
    }
}
impl<'p> Drop for PkeyGuardRefMut<'p> {
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

    pub fn deref(&self, access_rights: PkeyAccessRights) -> Result<PkeyGuardRef<'_>, super::MprotectError> {
        self.pkey.set_access_rights(access_rights)?;
        Ok(PkeyGuardRef::new(self))
    }

    pub fn deref_mut(&self, access_rights: PkeyAccessRights) -> Result<PkeyGuardRefMut<'_>, super::MprotectError> {
        self.pkey.set_access_rights(access_rights)?;
        Ok(PkeyGuardRefMut::new(self))
    }
}
