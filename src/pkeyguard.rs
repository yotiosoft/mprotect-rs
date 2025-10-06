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
pub enum PkeyGuardError {
    MprotectError(super::MprotectError),
    RegionGuardError(GuardError),
    InvalidRegionError,
}

/// Represents a memory region associated with a specific protection key (PKey)
/// and a defined access-rights policy.
///
/// The `AssociatedRegion` acts as a scoped controller that automatically
/// synchronizes and restores access rights when entering or leaving its scope.
/// It ensures that read and/or write operations are permitted only under
/// the current MPK configuration.
///
/// When an instance is created, its access rights are pushed onto the
/// [`PkeyGuard`]’s internal permissions stack. When dropped, the previous
/// state is automatically restored.
///
/// # Type Parameters
/// - `'p`: Lifetime bound to the associated [`PkeyGuard`].
/// - `A`: Allocator type managing the region.
/// - `T`: Element type stored in the region.
/// - `Rights`: Access-rights type implementing [`Access`].
///
/// # Example
/// ```rust
/// let guard = PkeyGuard::<MyAllocator, u8>::new(ReadWrite)?;
/// let mut region = RegionGuard::<MyAllocator, u8>::new(...)?;
///
/// // Associate region with read-only access
/// let associated = AssociatedRegion::<_, _, ReadOnly>::new(&mut region, &guard);
///
/// // Obtain a read guard (allowed)
/// let ref_guard = associated.ref_guard()?;
///
/// // Write access is prohibited here
/// ```
///
/// Upon drop, the original access rights from the `PkeyGuard` stack are restored.
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
    /// Creates a new associated region bound to a specific PKey and access rights.
    ///
    /// This method:
    /// 1. Initializes the access-rights type (`Rights`)
    /// 2. Pushes those rights onto the guard’s permission stack
    /// 3. Returns a scoped region that automatically manages access rights
    ///
    /// # Arguments
    /// - `region`: The target memory region to associate.
    /// - `pkey_guard`: The protection-key guard managing hardware-level rights.
    ///
    /// # Returns
    /// A new [`AssociatedRegion`] representing the scoped association.
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

    /// Ensures the current PKey permission state matches this region’s rights.
    ///
    /// If a mismatch is detected, it updates the hardware register (`PKRU`)
    /// using [`PKey::set_access_rights`].
    ///
    /// # Errors
    /// Returns [`MprotectError`] if the hardware update fails.
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

    /// Returns a read-only guard for the associated memory region.
    ///
    /// # Constraints
    /// This method is only available if the region's `Rights`
    /// type implements [`CanRead`].
    ///
    /// # Errors
    /// - [`PkeyGuardError::InvalidRegionError`]: If the region pointer is null.
    /// - [`PkeyGuardError::MprotectError`]: If permission synchronization fails.
    /// - [`PkeyGuardError::RegionGuardError`]: If the underlying region read fails.
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

    /// Returns a mutable guard for the associated memory region.
    ///
    /// # Constraints
    /// This method is only available if the region’s `Rights`
    /// type implements [`CanWrite`].
    ///
    /// # Errors
    /// - [`PkeyGuardError::InvalidRegionError`]: If the region pointer is null.
    /// - [`PkeyGuardError::MprotectError`]: If permission synchronization fails.
    /// - [`PkeyGuardError::RegionGuardError`]: If the underlying region write fails.
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
    /// Restores the previous PKey access rights when the region goes out of scope.
    ///
    /// This ensures that any temporary permission changes made by the region
    /// are reverted upon drop.  
    /// The `popped` flag prevents multiple pops for nested scopes.
    fn drop(&mut self) {
        if !self.popped.get() {
            // pop current access rights from stack
            self.pkey_guard.pop_permissions();
            self.popped.set(false);
        }
        //println!("Dropped AssociatedRegion, reset PKey access rights to {:?}", self.pkey_guard.current_access_rights.get());
    }
}

/// A scoped handler that manages an [`AssociatedRegion`] along with its
/// corresponding [`PkeyGuard`] for runtime permission control.
///
/// This type acts as a **high-level controller** for region–pkey associations.
/// It owns an [`AssociatedRegion`] that ties a memory region (`RegionGuard`) to
/// a protection key (`PkeyGuard`), and provides methods to update or transition
/// access rights dynamically.
///
/// Each time you call [`set_access_rights()`], the handler:
/// - Updates the underlying hardware protection key via `wrpkru`
/// - Pushes the new permission state onto the guard’s internal stack
/// - Returns a new [`AssociatedRegion`] object representing that access level
///
/// Dropping the handler or associated regions automatically restores
/// previous access rights.
///
/// # Type Parameters
/// - `'p`: Lifetime bound to the associated [`PkeyGuard`].
/// - `A`: Allocator type managing the memory region.
/// - `T`: Element type stored in the associated region.
/// - `Rights`: Current access-rights type bound by [`Access`] trait.
///
/// # Example
/// ```rust
/// // Create a new region associated with a PKey guard
/// let handler = guard.associate::<ReadWrite>(&mut region)?;
///
/// // Temporarily change access rights to read-only
/// let readonly_region = handler.set_access_rights::<ReadOnly>()?;
/// ```
///
/// After leaving scope, the original `ReadWrite` rights are restored automatically.
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
    /// Creates a new [`AssociatedRegionHandler`] for a given region and guard.
    ///
    /// This method associates a [`RegionGuard`] with a [`PkeyGuard`],
    /// applying the initial access rights specified by `Rights`.
    ///
    /// # Arguments
    /// - `region`: The memory region to associate with this protection key.
    /// - `pkey_guard`: The global protection-key guard controlling access rights.
    ///
    /// # Returns
    /// A new handler that controls the lifetime and permissions of the association.
    pub fn new(region: &mut RegionGuard<A, T>, pkey_guard: &'p PkeyGuard<A, T>) -> Self {
        AssociatedRegionHandler {
            associated_region: AssociatedRegion::new(region, pkey_guard),
            pkey_guard,
        }
    }

    /// Dynamically changes the access rights of the associated region.
    ///
    /// This method performs the following steps:
    /// 1. Calls `wrpkru` to update the hardware protection key to the new rights.
    /// 2. Pushes the new rights onto the `PkeyGuard`'s permission stack.
    /// 3. Returns a new [`AssociatedRegion`] that reflects the updated state.
    ///
    /// # Type Parameters
    /// - `NewRights`: The new access-rights type (e.g., `ReadOnly`, `ReadWrite`, `NoAccess`).
    ///
    /// # Returns
    /// - `Ok(AssociatedRegion<NewRights>)`: On successful update.
    /// - `Err(MprotectError)`: If the system call or `mprotect` operation fails.
    ///
    /// # Safety
    /// This operation invokes `wrpkru`, which directly updates CPU access rights.
    /// Incorrect usage or mismatched region states may cause access violations.
    ///
    /// # Example
    /// ```rust
    /// let mut handler = PkeyGuard::associate::<ReadWrite>(&mut region)?;
    /// let readonly = handler.set_access_rights::<ReadOnly>()?;
    /// ```
    pub fn set_access_rights<NewRights: access_rights::Access>(&'a mut self) -> Result<AssociatedRegion<'a, A, T, NewRights>, super::MprotectError> 
    where
        NewRights: access_rights::Access,
    {
        // Apply new hardware access rights via PKRU
        unsafe {
            self.pkey_guard.pkey.set_access_rights(NewRights::new().value())?;
        }
        println!("New PKey access rights set to {:?}", NewRights::new().value());

        // Mark current region as popped so previous permissions are not restored twice
        self.associated_region.popped.set(true);
        // Push the new permission state
        self.pkey_guard.push_permissions(NewRights::new().value());

        // Return a new associated region scoped to the new rights
        Ok(AssociatedRegion {
            region: self.associated_region.region,
            pkey_guard: self.pkey_guard,
            access_rights: NewRights::new(),
            popped: Cell::new(false),
        })
    }
}

/// A guard object that manages a single hardware protection key (`pkey`)
/// and its associated access-rights state.
///
/// The `PkeyGuard` is the central component for working with Intel MPK (Memory Protection Keys)
/// or similar hardware-backed page protection mechanisms. It encapsulates the lifecycle
/// of a protection key, including:
///
/// - Allocation of a new key via system calls (e.g. `pkey_alloc`)
/// - Applying access-rights to memory regions (read/write/none)
/// - Maintaining a stack of nested permission changes
///
/// # Type Parameters
/// - `A`: The allocator type used to manage memory regions associated with this key.
/// - `T`: The element type stored within those regions.
///
/// This struct is typically created with [`PkeyGuard::new()`] and then used to
/// associate memory regions via [`PkeyGuard::associate()`].  
/// Scoped region handlers (such as [`AssociatedRegion`] and [`AssociatedRegionHandler`])
/// use `PkeyGuard` internally to push and pop access rights safely.
///
/// # Example
/// ```rust
/// let guard = PkeyGuard::<MyAllocator, u8>::new(ReadWrite)?;
/// let mut region = RegionGuard::<MyAllocator, u8>::new(...)?;
///
/// // Associate region and access with `ReadOnly` rights
/// let handler = guard.associate::<ReadOnly>(&mut region)?;
/// ```
///
/// After leaving the region’s scope, previous access rights are automatically restored.
pub struct PkeyGuard<A, T> {
    pkey: PKey,
    current_access_rights: Cell<PkeyAccessRights>,
    permissions_stack: RefCell<Vec<PkeyAccessRights>>,
    _marker: std::marker::PhantomData<(A, T)>,
}

impl<A, T> PkeyGuard<A, T> {
    /// Creates a new `PkeyGuard` with the given default access rights.
    ///
    /// # Parameters
    /// - `default_access_rights`: The initial permissions (e.g. `ReadWrite`, `ReadOnly`, or `NoAccess`).
    ///
    /// # Returns
    /// - A new instance of `PkeyGuard`, holding a unique protection key (pkey).
    ///
    /// # Behavior
    /// - Allocates a new protection key using the underlying OS API (`pkey_alloc`).
    /// - Sets the key’s access rights to the provided default value.
    /// - Initializes an internal stack (`permissions_stack`) to manage nested access-right changes.
    ///
    /// This stack allows temporarily changing access rights (e.g., to `ReadOnly`) and safely
    /// restoring the previous permissions when leaving a scoped region.
    pub fn new<Access: access_rights::Access>(default_access_rights: Access) -> Result<Self, super::MprotectError> {
        let pkey = unsafe {
            PKey::new(default_access_rights.value())?
        };
        Ok(
            PkeyGuard {
                pkey,
                // Track the current access rights applied to the key.
                current_access_rights: Cell::new(default_access_rights.value()),
                // Initialize the permission stack with the default rights.
                permissions_stack: RefCell::new(vec![default_access_rights.value()]),
                _marker: std::marker::PhantomData,
            }
        )
    }

    /// Pops (removes) the top access rights from the permission stack,
    /// restoring the previous access state if available.
    ///
    /// # Behavior
    /// - Pops the last entry from the permission stack.
    /// - If another permission remains on the stack, the system’s pkey access
    ///   rights are reset to that previous state.
    ///
    /// This method is typically called automatically by `Drop` implementations
    /// when an associated region or handler goes out of scope.
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

    /// Pushes a new access-right value onto the stack and applies it immediately.
    ///
    /// # Parameters
    /// - `rights`: The new access rights to apply (e.g., `ReadOnly` or `ReadWrite`).
    ///
    /// # Behavior
    /// - The rights are pushed onto an internal stack for tracking nested changes.
    /// - The hardware key is updated to reflect this new access state.
    ///
    /// This mechanism allows nested permission changes to safely revert once
    /// a scope (e.g., `AssociatedRegion`) exits.
    fn push_permissions(&self, rights: PkeyAccessRights) {
        self.permissions_stack.borrow_mut().push(rights);

        //println!("[pushed permissions: {:?}]", rights);
        //println!("[Set pkey access rights from {:?} to {:?}]", self.current_access_rights.get(), rights);
        unsafe {
            self.pkey.set_access_rights(rights).expect("Failed to set pkey access rights");
        }
        self.current_access_rights.set(rights);
    }

    /// Returns a reference to the underlying `PKey` instance.
    ///
    /// # Note
    /// This function exposes the raw handle for advanced use cases such as
    /// associating multiple memory regions with the same pkey.
    pub fn pkey(&self) -> &PKey {
        &self.pkey
    }

    /// Associates this protection key with a given memory region.
    ///
    /// # Parameters
    /// - `region`: A mutable reference to a `RegionGuard` (memory region manager).
    ///
    /// # Type Parameters
    /// - `Rights`: The desired initial access rights for this region.
    ///
    /// # Returns
    /// - A new `AssociatedRegionHandler`, which can manage access-right transitions
    ///   within this region (e.g. switching from `ReadOnly` to `ReadWrite`).
    ///
    /// # Safety
    /// - Calls into low-level `pkey_mprotect` to bind a protection key to the given memory region.
    /// - Updates the hardware key’s access rights to match the `Rights` type parameter.
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
