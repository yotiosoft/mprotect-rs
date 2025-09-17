use crate::{mprotect::*, MprotectError};

use std::cell::Cell;
use std::rc::Rc;
use std::ops::{Deref, DerefMut};
pub struct RegionGuard<A: allocator::Allocator<T>, T> {
    memory: UnsafeProtectedRegion<A, T>,
    generation: Rc<Cell<u64>>,
    default_access_rights: AccessRights,
    access_rights: Rc<Cell<AccessRights>>,
}

impl<A: allocator::Allocator<T>, T> RegionGuard<A, T> {
    pub fn new(access_rights: AccessRights) -> Result<Self, super::MprotectError> {
        let generation = Rc::new(Cell::new(0));
        let memory = UnsafeProtectedRegion::new(access_rights)?;
        Ok(
            RegionGuard {
                memory,
                generation,
                default_access_rights: access_rights,
                access_rights: Rc::new(Cell::new(access_rights)),
            }
        )
    }

    pub fn invalidate(&self) {
        let current_gen = self.generation.get();
        self.generation.set(current_gen.wrapping_add(1));
    }

    pub fn read(&self) -> Result<GuardRef<'_, A, T>, GuardError> {
        if !self.access_rights.get().contains(AccessRights::Read) {
            self.access_rights.set(self.access_rights.get().add(AccessRights::Read));
            self.memory.set_access(self.access_rights.get()).map_err(GuardError::CannotSetAccessRights)?;
        }

        let gen = self.generation.get();
        Ok(GuardRef {
            ptr: self.memory.as_ref() as *const T,
            mem: &self.memory,
            gen,
            generation: Rc::clone(&self.generation),
            default_access_rights: self.default_access_rights,
            access_rights: Rc::clone(&self.access_rights),
        })
    }

    pub fn write(&mut self) -> Result<GuardRefMut<'_, A, T>, GuardError> {
        if !self.access_rights.get().contains(AccessRights::Write) {
            self.access_rights.set(self.access_rights.get().add(AccessRights::Write));
            self.memory.set_access(self.access_rights.get()).map_err(GuardError::CannotSetAccessRights)?;
        }

        let gen = self.generation.get();
        Ok(GuardRefMut {
            ptr: self.memory.as_mut() as *mut T,
            mem: &mut self.memory,
            gen,
            generation: Rc::clone(&self.generation),
            default_access_rights: self.default_access_rights,
            access_rights: Rc::clone(&self.access_rights),
        })
    }
}

#[derive(Debug)]
pub enum GuardError {
    InvalidGeneration,
    InvalidAccessRights,
    CannotSetAccessRights(MprotectError),
}

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardError::InvalidGeneration => write!(f, "Invalid generation: the guard reference is no longer valid"),
            GuardError::InvalidAccessRights => write!(f, "Invalid access rights: the memory region does not allow the requested access"),
            GuardError::CannotSetAccessRights(err) => write!(f, "Cannot set access rights: {}", err),
        }
    }
}

pub struct GuardRef<'a, A: allocator::Allocator<T>, T> {
    ptr: *const T,
    mem: &'a UnsafeProtectedRegion<A, T>,
    gen: u64,
    generation: Rc<Cell<u64>>,
    default_access_rights: AccessRights,
    access_rights: Rc<Cell<AccessRights>>,
}

impl<'a, A: allocator::Allocator<T>, T> GuardRef<'a, A, T> {
    pub fn is_valid(&self) -> bool {
        self.generation.get() == self.gen
    }

    pub fn with<F, R>(&self, f: F) -> Result<R, GuardError>
    where 
        F: FnOnce(&T) -> R,
    {
        if self.is_valid() {
            unsafe { Ok(f(&*self.ptr)) }
        } else {
            Err(GuardError::InvalidGeneration)
        }
    }
}

impl<'a, A: allocator::Allocator<T>, T> Deref for GuardRef<'a, A, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        if self.is_valid() {
            unsafe { &*self.ptr }
        } else {
            panic!("Failed to deref GuardRef: invalid generation");
        }
    }
}

impl<'a, A: allocator::Allocator<T>, T> Drop for GuardRef<'a, A, T> {
    fn drop(&mut self) {
        if self.generation.get() == self.gen {
            if self.default_access_rights.contains(AccessRights::Read) {
                // The default access rights already include Read, so no need to change
                // because dropping a read guard should not remove read access if it was there by default
                println!("Drop read guard: default access includes Read, no change needed");
                return;
            } else if self.access_rights.get().contains(AccessRights::Read) {
                let new_access = self.access_rights.get().remove(AccessRights::Read);
                let _ = self.mem.set_access(new_access);
                self.access_rights.set(new_access);
                println!("Drop read guard: removed Read access, new access rights: {:?}", new_access);
            }
        }
    }
}

pub struct GuardRefMut<'a, A: allocator::Allocator<T>, T> {
    ptr: *mut T,
    mem: &'a UnsafeProtectedRegion<A, T>,
    gen: u64,
    generation: Rc<Cell<u64>>,
    default_access_rights: AccessRights,
    access_rights: Rc<Cell<AccessRights>>,
}

impl<'a, A: allocator::Allocator<T>, T> GuardRefMut<'a, A, T> {
    pub fn is_valid(&self) -> bool {
        self.generation.get() == self.gen
    }

    pub fn with<F, R>(&mut self, f: F) -> Result<R, GuardError>
    where 
        F: FnOnce(&mut T) -> R,
    {
        if self.is_valid() {
            unsafe { Ok(f(&mut *self.ptr)) }
        } else {
            Err(GuardError::InvalidGeneration)
        }
    }
}

impl<'a, A: allocator::Allocator<T>, T> Deref for GuardRefMut<'a, A, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        if self.is_valid() {
            unsafe { &*self.ptr }
        } else {
            panic!("Failed to deref GuardRefMut: invalid generation");
        }
    }
}

impl<'a, A: allocator::Allocator<T>, T> DerefMut for GuardRefMut<'a, A, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        if self.is_valid() {
            unsafe { &mut *self.ptr }
        } else {
            panic!("Failed to deref_mut GuardRefMut: invalid generation");
        }
    }
}

impl<A: allocator::Allocator<T>, T> Drop for GuardRefMut<'_, A, T> {
    fn drop(&mut self) {
        if self.is_valid() {
            println!("default_access_rights: {:?}, current access_rights: {:?}", self.default_access_rights, self.access_rights.get());
            if self.default_access_rights.contains(AccessRights::ReadWrite) {
                // The default access rights already include ReadWrite, so no need to change
                // because dropping a write guard should not remove read/write access if it was there by default
                println!("Drop write guard: default access includes ReadWrite, no change needed");
                return;
            } else if !self.default_access_rights.contains(AccessRights::Write) && self.access_rights.get().contains(AccessRights::Write) {
                let new_access = self.access_rights.get().remove(AccessRights::Write);
                let _ = self.mem.set_access(new_access);
                self.access_rights.set(new_access);
                println!("Drop write guard: removed Write access, new access rights: {:?}", new_access);
                return;
            } else if !self.default_access_rights.contains(AccessRights::Read) && self.access_rights.get().contains(AccessRights::Read) {
                let new_access = self.access_rights.get().remove(AccessRights::Read);
                let _ = self.mem.set_access(new_access);
                self.access_rights.set(new_access);
                println!("Drop write guard: removed Read access, new access rights: {:?}", new_access);
                return;
            } else if self.access_rights.get().contains(AccessRights::Read) || self.access_rights.get().contains(AccessRights::Write) {
                let new_access = self.access_rights.get().remove(AccessRights::ReadWrite);
                let _ = self.mem.set_access(new_access);
                self.access_rights.set(new_access);
                println!("Drop write guard: removed ReadWrite access, new access rights: {:?}", new_access);
                return;
            }
        }
    }
}
