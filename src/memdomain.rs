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

/// Represents possible errors when working with `PkeyGuard` and its regions.
#[derive(Debug)]
pub enum MemoryDomainError {
    MprotectError(super::MprotectError),
    RegionGuardError(GuardError),
    InvalidRegionError,
}

pub struct MemoryDomain<'p, A: allocator::Allocator<T>, T, Rights>
where 
    Rights: access_rights::Access,
{
    region: *mut RegionGuard<A, T>,
    pkey_guard: &'p PkeyGuard<A, T>,
    access_rights: Rights,
    popped: Cell<bool>,

    memory: UnsafeProtectedRegion<A, T>,
    generation: Rc<Cell<u64>>,
    default_access_rights: AccessRights,
    access_rights: Rc<Cell<AccessRights>>,
}
