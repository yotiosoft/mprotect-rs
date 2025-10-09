use crate::{mprotect::*, MprotectError};

use std::cell::Cell;
use std::rc::Rc;
use std::ops::{ Deref, DerefMut };

/// A guard object that manages a protected memory region and its access rights.
///
/// `RegionGuard` encapsulates ownership and lifetime management of a memory region
/// allocated through a custom allocator (`allocator::Allocator<T>`).  
/// It provides safe, reference-counted control over access permissions and 
/// integrates with hardware memory protection mechanisms.
pub struct RegionGuard<A: allocator::Allocator<T>, T> {
    memory: UnsafeProtectedRegion<A, T>,
    generation: Rc<Cell<u64>>,
    default_access_rights: AccessRights,
    access_rights: Rc<Cell<AccessRights>>,
}

impl<A: allocator::Allocator<T>, T> RegionGuard<A, T> {
    /// Creates a new protected memory region with the given access rights.
    ///
    /// Allocates memory through the custom allocator and applies initial access
    /// rights using hardware protection keys such as mprotect.
    ///
    /// # Arguments
    /// 
    /// - `access_rights`: The initial protection flags.
    ///
    /// # Returns
    /// 
    /// - `Ok(RegionGuard)`: On success.
    /// - `Err(MprotectError)`: If memory allocation or protection setup fails.
    pub fn new<R: AllAccessesTrait>(access_rights: R) -> Result<Self, super::MprotectError> {
        let generation = Rc::new(Cell::new(0));
        let memory = unsafe {
            UnsafeProtectedRegion::new(access_rights.value())?
        };
        Ok(
            RegionGuard {
                memory,
                generation,
                default_access_rights: access_rights.value(),
                access_rights: Rc::new(Cell::new(access_rights.value())),
            }
        )
    }

    /// Invalidates the current generation of this region.
    ///
    /// Used to mark existing references as outdated.
    pub fn invalidate(&self) {
        let current_gen = self.generation.get();
        self.generation.set(current_gen.wrapping_add(1));
    }

    /// Grants read access and returns an immutable guard.
    ///
    /// Updates protection flags if necessary before returning a reference.
    ///
    /// # Returns
    /// 
    /// - `Ok(GuardRef)`: Read access wrapper.
    /// - `Err(GuardError)`: If access rights cannot be updated.
    pub fn read<'a>(&'a self) -> Result<GuardRef<'a, A, T>, GuardError> {
        if !self.access_rights.get().has(AccessRights::READ) {
            self.access_rights.set(self.access_rights.get().add(AccessRights::READ));
            unsafe {
                self.memory.set_access(self.access_rights.get()).map_err(GuardError::CannotSetAccessRights)?;
            }
        }

        let gen = self.generation.get();
        Ok(GuardRef {
            ptr: unsafe { self.memory.as_ref() },
            mem: &self.memory,
            gen,
            generation: Rc::clone(&self.generation),
            default_access_rights: self.default_access_rights,
            access_rights: Rc::clone(&self.access_rights),
        })
    }

    /// Grants write access and returns a mutable guard.
    ///
    /// Enables write permission if not already active.
    /// 
    /// # Returns
    /// 
    /// - `Ok(GuardRefMut)`: Write access wrapper.
    /// - `Err(GuardError)`: If access rights cannot be updated.
    pub fn write<'a>(&'a mut self) -> Result<GuardRefMut<'a, A, T>, GuardError> {
        if !self.access_rights.get().contains(AccessRights::WRITE) {
            self.access_rights.set(self.access_rights.get().add(AccessRights::WRITE));
            unsafe {
                self.memory.set_access(self.access_rights.get()).map_err(GuardError::CannotSetAccessRights)?;
            }
        }

        let gen = self.generation.get();
        Ok(GuardRefMut {
            ptr: unsafe { self.memory.as_mut() as *mut T },
            mem: &mut self.memory,
            gen,
            generation: Rc::clone(&self.generation),
            default_access_rights: self.default_access_rights,
            access_rights: Rc::clone(&self.access_rights),
        })
    }

    /// Returns a read-only guard for custom access rights.
    ///
    /// Automatically synchronizes protection flags if missing.
    /// 
    /// # Arguments
    /// 
    /// - `access_rights`: Desired access rights implementing `ReadAllowedTrait`.
    /// 
    /// # Returns
    /// 
    /// - `Ok(GuardRef)`: Read access wrapper.
    /// - `Err(GuardError)`: If access rights cannot be updated.
    pub fn deref<R: ReadAllowedTrait>(&self, access_rights: R) -> Result<GuardRef<'_, A, T>, GuardError> {
        if !self.access_rights.get().contains(access_rights.value()) {
            self.access_rights.set(self.access_rights.get().add(access_rights.value()));
            unsafe {
                self.memory.set_access(self.access_rights.get()).map_err(GuardError::CannotSetAccessRights)?;
            }
        }
        
        let gen = self.generation.get();
        Ok(GuardRef {
            ptr: unsafe { self.memory.as_ref() },
            mem: &self.memory,
            gen,
            generation: Rc::clone(&self.generation),
            default_access_rights: self.default_access_rights,
            access_rights: Rc::clone(&self.access_rights),
        })
    }

    /// Returns a mutable guard for custom access rights.
    ///
    /// Automatically synchronizes protection flags if missing.
    /// 
    /// # Arguments
    /// 
    /// - `access_rights`: Desired access rights implementing `WriteAllowedTrait`.
    /// 
    /// # Returns
    /// 
    /// - `Ok(GuardRefMut)`: Write access wrapper.
    /// - `Err(GuardError)`: If access rights cannot be updated.
    pub fn deref_mut<R: WriteAllowedTrait>(&mut self, access_rights: R) -> Result<GuardRefMut<'_, A, T>, GuardError> {
        if !self.access_rights.get().contains(access_rights.value()) {
            self.access_rights.set(self.access_rights.get().add(access_rights.value()));
            unsafe {
                self.memory.set_access(self.access_rights.get()).map_err(GuardError::CannotSetAccessRights)?;
            }
        }

        let gen = self.generation.get();
        Ok(GuardRefMut {
            ptr: unsafe { self.memory.as_mut() as *mut T },
            mem: &mut self.memory,
            gen,
            generation: Rc::clone(&self.generation),
            default_access_rights: self.default_access_rights,
            access_rights: Rc::clone(&self.access_rights),
        })
    }

    /// Returns the current access rights of this region.
    /// 
    /// # Returns
    /// 
    /// The current `AccessRights` flags.
    pub fn access_rights(&self) -> AccessRights {
        self.access_rights.get()
    }

    /// Returns a reference to the underlying protected memory region.
    ///
    /// # Safety
    /// 
    /// Direct access may bypass protection checks. Use guards when possible.
    /// 
    /// # Returns
    /// 
    /// A reference to the `UnsafeProtectedRegion`.
    pub unsafe fn get_region(&self) -> &UnsafeProtectedRegion<A, T> {
        &self.memory
    }

    /// Returns the length (in bytes) of the protected region.
    /// 
    /// # Returns
    /// 
    /// The size of the memory region in bytes.
    pub fn get_region_len(&self) -> usize {
        self.memory.len()
    }
}

/// Represents possible errors that can occur while managing guarded memory access.
///
/// These errors typically indicate invalid or unsafe memory operations detected
/// during access control or permission changes.
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

/// A read-only smart reference to a protected memory region.
///
/// `GuardRef` provides safe, temporary access to memory controlled by `RegionGuard`.
/// It validates the reference against a generation counter to prevent use-after-invalidate
/// and automatically updates memory access rights when dropped.
///
/// # Safety
/// 
/// - Dereferencing or using this guard after `invalidate()` is undefined behavior.
/// - Validity should always be checked using [`is_valid()`].
pub struct GuardRef<'a, A: allocator::Allocator<T>, T> {
    ptr: &'a T,
    mem: &'a UnsafeProtectedRegion<A, T>,
    gen: u64,
    generation: Rc<Cell<u64>>,
    default_access_rights: AccessRights,
    access_rights: Rc<Cell<AccessRights>>,
}

impl<'a, A: allocator::Allocator<T>, T> GuardRef<'a, A, T> {
    /// Returns `true` if this guard is still valid (not invalidated).
    /// 
    /// # Returns
    /// 
    /// `true` if valid, `false` if invalidated.
    pub fn is_valid(&self) -> bool {
        self.generation.get() == self.gen
    }

    /// Executes a closure on the referenced data if still valid.
    ///
    /// Returns an error if the reference has been invalidated.
    /// 
    /// # Arguments
    /// 
    /// - `f`: Closure to execute with the referenced data.
    /// 
    /// # Returns
    /// 
    /// - `Ok(R)`: Result of the closure if valid.
    /// - `Err(GuardError::InvalidGeneration)`: If invalidated.
    pub fn with<F, R>(&self, f: F) -> Result<R, GuardError>
    where 
        F: FnOnce(&T) -> R,
    {
        if self.is_valid() {
            Ok(f(&*self.ptr))
        } else {
            Err(GuardError::InvalidGeneration)
        }
    }

    /// Returns a raw pointer to the underlying data.
    ///
    /// # Safety
    /// 
    /// The caller must ensure the guard is valid before dereferencing.
    /// 
    /// # Returns
    /// 
    /// A raw pointer to the data.
    pub unsafe fn ptr(&self) -> *const T {
        self.ptr as *const T
    }
}

impl<'a, A: allocator::Allocator<T>, T> Deref for GuardRef<'a, A, T> {
    type Target = T;

    /// Dereferences the guarded reference if valid, panicking otherwise.
    fn deref(&self) -> &Self::Target {
        if self.is_valid() {
            &*self.ptr
        } else {
            panic!("Failed to deref GuardRef: invalid generation");
        }
    }
}

impl<'a, A: allocator::Allocator<T>, T> Drop for GuardRef<'a, A, T> {
    /// Restores access rights when the guard is dropped.
    ///
    /// If `READ` access was granted temporarily, it is removed
    /// unless it was part of the default access rights.
    fn drop(&mut self) {
        if self.generation.get() == self.gen {
            if self.default_access_rights.contains(AccessRights::READ) {
                // The default access rights already include Read, so no need to change
                // because dropping a read guard should not remove read access if it was there by default
                return;
            } else if self.access_rights.get().contains(AccessRights::READ) {
                let new_access = self.access_rights.get().minus(AccessRights::READ);
                let _ = unsafe { self.mem.set_access(new_access) };
                self.access_rights.set(new_access);
            }
        }
    }
}

/// A mutable guard that provides controlled access to a protected memory region.
///
/// `GuardRefMut` ensures safe temporary access to a memory region whose permissions
/// are dynamically managed. When dropped, it restores access rights to their original state.
/// 
/// # Safety
/// 
/// - Dereferencing or using this guard after `invalidate()` is undefined behavior.
/// - Validity should always be checked using [`is_valid()`].
pub struct GuardRefMut<'a, A: allocator::Allocator<T>, T> {
    ptr: *mut T,
    mem: &'a UnsafeProtectedRegion<A, T>,
    gen: u64,
    generation: Rc<Cell<u64>>,
    default_access_rights: AccessRights,
    access_rights: Rc<Cell<AccessRights>>,
}

impl<'a, A: allocator::Allocator<T>, T> GuardRefMut<'a, A, T> {
    /// Returns `true` if this guard is still valid.
    ///
    /// A guard becomes invalid when the region's generation counter changes.
    /// 
    /// # Returns
    /// 
    /// `true` if valid, `false` if invalidated.
    pub fn is_valid(&self) -> bool {
        self.generation.get() == self.gen
    }

    /// Executes the given closure if this guard is valid.
    ///
    /// # Errors
    ///
    /// Returns [`GuardError::InvalidGeneration`] if the guard is no longer valid.
    ///
    /// # Safety
    ///
    /// This method temporarily provides a mutable reference
    /// to the protected data if valid.
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

    /// Returns a shared reference to the underlying data.
    ///
    /// # Panics
    ///
    /// Panics if the guard has been invalidated.
    fn deref(&self) -> &Self::Target {
        if self.is_valid() {
            unsafe { &*self.ptr }
        } else {
            panic!("Failed to deref GuardRefMut: invalid generation");
        }
    }
}

impl<'a, A: allocator::Allocator<T>, T> DerefMut for GuardRefMut<'a, A, T> {
    /// Returns a mutable reference to the underlying data.
    ///
    /// # Panics
    ///
    /// Panics if the guard has been invalidated.
    fn deref_mut(&mut self) -> &mut Self::Target {
        if self.is_valid() {
            unsafe { &mut *self.ptr }
        } else {
            panic!("Failed to deref_mut GuardRefMut: invalid generation");
        }
    }
}

impl<A: allocator::Allocator<T>, T> Drop for GuardRefMut<'_, A, T> {
    /// Restores the region's access rights when the guard is dropped.
    ///
    /// If the guard temporarily granted `READ` or `WRITE` access,
    /// these rights are revoked unless they were part of the region's
    /// original default access rights.
    fn drop(&mut self) {
        if self.is_valid() {
            if self.default_access_rights.has(AccessRights::READ_WRITE) {
                // The default access rights already include ReadWrite, so no need to change
                // because dropping a write guard should not remove read/write access if it was there by default
                return;
            } else if !self.default_access_rights.has(AccessRights::WRITE) && self.access_rights.get().has(AccessRights::WRITE) {
                let new_access = self.access_rights.get().minus(AccessRights::WRITE);
                let _ = unsafe { self.mem.set_access(new_access) };
                self.access_rights.set(new_access);
                return;
            } else if !self.default_access_rights.has(AccessRights::READ) && self.access_rights.get().has(AccessRights::READ) {
                let new_access = self.access_rights.get().minus(AccessRights::READ);
                let _ = unsafe { self.mem.set_access(new_access) };
                self.access_rights.set(new_access);
                return;
            } else if self.access_rights.get().has(AccessRights::READ) || self.access_rights.get().has(AccessRights::WRITE) {
                let new_access = self.access_rights.get().minus(AccessRights::READ_WRITE);
                let _ = unsafe { self.mem.set_access(new_access) };
                self.access_rights.set(new_access);
                return;
            }
        }
    }
}
