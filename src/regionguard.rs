use crate::mprotect::*;

use std::cell::Cell;
use std::rc::Rc;
use std::ops::Deref;

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

    pub fn lock(&self) -> AccessGuard<T> {
        let generation = self.generation.get();
        AccessGuard {
            ptr: &self.memory as *const UnsafeProtectedRegion<A, T> as *const T,
            generation: Rc::clone(&self.generation),
            valid_generation: generation,
        }
    }
}

#[derive(Debug)]
pub enum AccessGuardError {
    InvalidGeneration,
}

struct AccessGuard<T> {
    ptr: *const T,
    generation: Rc<Cell<u64>>,
    valid_generation: u64,
}

impl<T> AccessGuard<T> {
    pub fn get(&self) -> Result<&T, AccessGuardError> {
        if self.generation.get() != self.valid_generation {
            Err(AccessGuardError::InvalidGeneration)
        }
        else {
            unsafe {
                Ok(&*self.ptr)
            }
        }
    }

    pub fn get_mut(&mut self) -> Result<&mut T, AccessGuardError> {
        if self.generation.get() != self.valid_generation {
            Err(AccessGuardError::InvalidGeneration)
        }
        else {
            unsafe {
                Ok(&mut *(self.ptr as *mut T))
            }
        }
    }
}

pub struct GuardRef<'a, T> {
    guard: &'a AccessGuard<T>,
}

impl<'a, T> GuardRef<'a, T> {
    pub fn get(&self) -> Result<&T, AccessGuardError> {
        self.guard.get()
    }
}

impl<'a, T> Deref for GuardRef<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.guard.get().expect("Failed to deref GuardRef")
    }
}
