use crate::mprotect::*;

use std::cell::Cell;
use std::rc::Rc;
use std::ops::{Deref, DerefMut};

pub struct RegionGuard<A: allocator::Allocator<T>, T> {
    memory: UnsafeProtectedRegion<A, T>,
    generation: Rc<Cell<u64>>,
}

impl<A: allocator::Allocator<T>, T> RegionGuard<A, T> {
    pub fn new(access_rights: AccessRights) -> Result<Self, super::MprotectError> {
        let generation = Rc::new(Cell::new(0));
        let memory = UnsafeProtectedRegion::new(access_rights)?;
        Ok(
            RegionGuard {
                memory,
                generation,
            }
        )
    }

    pub fn set_access(&mut self, access_rights: AccessRights) -> Result<(), super::MprotectError> {
        self.memory.set_access(access_rights)?;
        self.invalidate();
        Ok(())
    }

    pub fn invalidate(&self) {
        let current_gen = self.generation.get();
        self.generation.set(current_gen.wrapping_add(1));
    }

    pub fn read(&self) -> Result<GuardRef<'_, A, T>, GuardError> {
        let access_rights = self.memory.region_access_rights();
        if !access_rights.contains(AccessRights::Read) {
            return Err(GuardError::InvalidAccessRights);
        }

        let gen = self.generation.get();
        Ok(GuardRef {
            ptr: &self.memory,
            gen,
            generation: Rc::clone(&self.generation),
        })
    }

    pub fn write(&mut self) -> Result<GuardRefMut<'_, A, T>, GuardError> {
        let access_rights = self.memory.region_access_rights();
        if !access_rights.contains(AccessRights::Write) {
            println!("Write access denied: current rights = {:?}", access_rights);
            return Err(GuardError::InvalidAccessRights);
        }
        println!("Write access granted: current rights = {:?}", access_rights);

        let gen = self.generation.get();
        Ok(GuardRefMut {
            ptr: &mut self.memory,
            gen,
            generation: Rc::clone(&self.generation),
        })
    }
}

#[derive(Debug)]
pub enum GuardError {
    InvalidGeneration,
    InvalidAccessRights,
}

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardError::InvalidGeneration => write!(f, "Invalid generation: the guard reference is no longer valid"),
            GuardError::InvalidAccessRights => write!(f, "Invalid access rights: the memory region does not allow the requested access"),
        }
    }
}

pub struct GuardRef<'a, A: allocator::Allocator<T>, T> {
    ptr: &'a UnsafeProtectedRegion<A, T>,
    gen: u64,
    generation: Rc<Cell<u64>>,
}

impl<'a, A: allocator::Allocator<T>, T> GuardRef<'a, A, T> {
    pub fn check_validity(&self) -> Result<&T, GuardError> {
        if self.generation.get() == self.gen {
            Ok(&self.ptr.as_ref())
        } else {
            Err(GuardError::InvalidGeneration)
        }
    }
}

impl<'a, A: allocator::Allocator<T>, T> Deref for GuardRef<'a, A, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.check_validity().expect("Failed to deref GuardRef")
    }
}

pub struct GuardRefMut<'a, A: allocator::Allocator<T>, T> {
    ptr: &'a mut UnsafeProtectedRegion<A, T>,
    gen: u64,
    generation: Rc<Cell<u64>>,
}

impl<'a, A: allocator::Allocator<T>, T> GuardRefMut<'a, A, T> {
    pub fn is_valid(&self) -> bool {
        self.generation.get() == self.gen
    }
}

impl<'a, A: allocator::Allocator<T>, T> Deref for GuardRefMut<'a, A, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        if self.is_valid() {
            self.ptr.as_ref()
        } else {
            panic!("Failed to deref GuardRefMut: invalid generation");
        }
    }
}

impl<'a, A: allocator::Allocator<T>, T> DerefMut for GuardRefMut<'a, A, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        if self.is_valid() {
            self.ptr.as_mut()
        } else {
            panic!("Failed to deref_mut GuardRefMut: invalid generation");
        }
    }
}
