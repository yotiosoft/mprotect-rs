use core::panic;

use std::ptr::NonNull;

pub mod allocator;

pub mod access_rights;
pub use access_rights::AccessRights;
pub use access_rights::access_permissions as AccessPermissions;
pub use AccessPermissions::{ ReadAllowed, WriteAllowed, ExecuteAllowed, NoAccessAllowed, AllAccesses };
pub use AccessPermissions::{ ReadAllowedTrait, WriteAllowedTrait, ExecuteAllowedTrait, NoAccessAllowedTrait, AllAccessesTrait };

/// A low-level memory region protected by `mprotect` or `pkey_mprotect` system calls.
/// 
/// This struct represents a memory region with controlled access permissions. It uses
/// a specified allocator (e.g., `Mmap` or `Jmalloc`) to allocate and deallocate memory,
/// and can optionally be associated with a protection key for fine-grained access control.
/// 
/// # Safety
/// 
/// `UnsafeProtectedRegion` provides **unsafe**, low-level access to the memory region
/// and does **not** enforce access rights at the Rust type system level. Users must:
/// - Manually respect the access rights set for the memory region
/// - Understand that violating access rights will cause a **segmentation fault**
/// - Use `RegionGuard` for safer, type-enforced access control
/// 
/// # Memory Management
/// 
/// The memory region is:
/// - Allocated on creation using the specified allocator
/// - Automatically deallocated when the `UnsafeProtectedRegion` instance is dropped
/// - Page-aligned (for `Mmap` allocator) to work with `mprotect` system calls
/// 
/// # Type Parameters
/// 
/// - `A`: The allocator type that implements the `Allocator<T>` trait
/// - `T`: The type of data to be stored in the memory region
/// 
/// # Fields
/// 
/// - `ptr`: A non-null pointer to the allocated memory region
/// - `len`: The length of the allocated memory region in bytes
/// - `pkey_id`: An optional protection key ID if associated with a pkey
/// - `allocator`: The allocator instance used to manage the memory region
/// 
/// # Example
/// 
/// ```no_run
/// use mprotect_rs::{UnsafeProtectedRegion, AccessRights, allocator::Mmap};
/// 
/// unsafe {
///     // Create a protected memory region for an i32
///     let mut region = UnsafeProtectedRegion::<Mmap, i32>::new(AccessRights::READ_WRITE)?;
///     
///     // Write to the region
///     *region.as_mut() = 42;
///     
///     // Change access rights to read-only
///     region.set_access(AccessRights::READ)?;
///     
///     // Read from the region
///     let value = *region.as_ref();
///     assert_eq!(value, 42);
///     
///     // Writing now would cause a segmentation fault!
///     // *region.as_mut() = 0; // ❌ SEGFAULT
/// }
/// # Ok::<(), mprotect_rs::MprotectError>(())
/// ```
pub struct UnsafeProtectedRegion<A: allocator::Allocator<T>, T> {
    ptr: NonNull<T>,
    len: usize,
    pkey_id: Option<u32>,
    allocator: allocator::MemoryRegion<A, T>,
}

/// Implementation of methods for `UnsafeProtectedRegion`.
impl<A: allocator::Allocator<T>, T> UnsafeProtectedRegion<A, T> {
    /// Allocates a new memory region with the specified access rights.
    /// 
    /// This method creates a new `UnsafeProtectedRegion` by allocating memory using
    /// the specified allocator and setting the initial page-level access permissions.
    /// The memory region is not associated with any protection key initially.
    /// 
    /// # Safety
    /// 
    /// This function is unsafe because:
    /// - It allocates uninitialized memory that must be properly initialized before use
    /// - The caller must respect the access rights set for the memory region
    /// - Violating access rights will cause a segmentation fault
    /// 
    /// # Arguments
    /// 
    /// - `access_rights`: The initial page-level access rights for the memory region
    /// 
    /// # Returns
    /// 
    /// - `Ok(UnsafeProtectedRegion)`: On successful allocation
    /// - `Err(MprotectError::MemoryAllocationFailed)`: If memory allocation fails
    /// 
    /// # Example
    /// 
    /// ```no_run
    /// # use mprotect_rs::{UnsafeProtectedRegion, AccessRights, allocator::Mmap};
    /// unsafe {
    ///     let region = UnsafeProtectedRegion::<Mmap, i32>::new(AccessRights::READ_WRITE)?;
    ///     // Use the region...
    /// }
    /// # Ok::<(), mprotect_rs::MprotectError>(())
    /// ```
    pub unsafe fn new(access_rights: AccessRights) -> Result<Self, super::MprotectError> {
        let allocator = allocator::MemoryRegion::allocate(&access_rights)
            .map_err(|e| super::MprotectError::MemoryAllocationFailed(match e {
                allocator::AllocatorError::MmapFailed(errno) => errno,
                allocator::AllocatorError::MunmapFailed(errno) => errno,
                allocator::AllocatorError::LayoutError => -1,
            }))?;
        Ok(Self {
            ptr: NonNull::new(allocator.ptr()).ok_or(super::MprotectError::MemoryAllocationFailed(-1))?,
            len: std::mem::size_of::<T>(),
            pkey_id: None,
            allocator,
        })
    }

    /// Changes the access rights of the memory region using `mprotect`.
    /// 
    /// This method modifies the page-level access permissions in the page table entries (PTEs)
    /// using the `mprotect` system call. The change takes effect immediately for the entire
    /// memory region.
    /// 
    /// **Note**: If the memory region is associated with a protection key, both the page-level
    /// permissions (set by this method) and the protection key permissions (set via PKRU register)
    /// apply. The most restrictive permission takes effect.
    /// 
    /// # Safety
    /// 
    /// This function is unsafe because:
    /// - It directly modifies memory protection state
    /// - The caller must ensure the memory region is valid
    /// - Setting incorrect permissions can cause program instability
    /// 
    /// # Arguments
    /// 
    /// - `access_rights`: The new page-level access rights to be set
    /// 
    /// # Returns
    /// 
    /// - `Ok(())`: On successful permission change
    /// - `Err(MprotectError::MprotectFailed)`: If the `mprotect` system call fails
    /// 
    /// # Example
    /// 
    /// ```no_run
    /// # use mprotect_rs::{UnsafeProtectedRegion, AccessRights, allocator::Mmap};
    /// # unsafe {
    /// let region = UnsafeProtectedRegion::<Mmap, i32>::new(AccessRights::READ_WRITE)?;
    /// 
    /// // Change to read-only
    /// region.set_access(AccessRights::READ)?;
    /// # Ok::<(), mprotect_rs::MprotectError>(())
    /// # }
    /// ```
    pub unsafe fn set_access(&self, access_rights: AccessRights) -> Result<(), super::MprotectError> {
        let ret = unsafe {
            libc::mprotect(
                self.ptr.as_ptr() as *mut libc::c_void,
                self.len,
                access_rights.to_i32(),
            )
        };
        if ret != 0 {
            let err_no = std::io::Error::last_os_error().raw_os_error().unwrap();
            return Err(super::MprotectError::MprotectFailed(err_no));
        }
        Ok(())
    }

    /// Returns a raw pointer to the allocated memory region.
    /// 
    /// This method provides direct access to the underlying memory pointer.
    /// The caller must ensure that:
    /// - The pointer is used safely within the memory region's bounds
    /// - Access respects the current access rights
    /// - The pointer is not used after the region is dropped
    /// 
    /// # Returns
    /// 
    /// A mutable raw pointer to the allocated memory region.
    pub fn ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }

    /// Returns the length of the allocated memory region in bytes.
    /// 
    /// For most allocators, this will be the size of type `T`, potentially
    /// rounded up to page size for the `Mmap` allocator.
    /// 
    /// # Returns
    /// 
    /// The length of the allocated memory region in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns the protection key ID associated with the memory region, if any.
    /// 
    /// This method returns the ID of the protection key that has been associated with
    /// this memory region using `pkey_mprotect`. If no protection key is associated,
    /// it returns `None`.
    /// 
    /// # Returns
    /// 
    /// - `Some(u32)`: The protection key ID if the region is associated with a pkey
    /// - `None`: If no protection key is associated with this region
    pub fn pkey(&self) -> Option<u32> {
        self.pkey_id
    }

    /// Returns a mutable reference to the data stored in the memory region.
    /// 
    /// # Safety
    /// 
    /// This function is unsafe because:
    /// - It assumes the memory has been properly initialized
    /// - The caller must respect the current access rights
    /// - Violating write permissions will cause a segmentation fault
    /// - The returned reference's lifetime is tied to the region
    /// 
    /// # Returns
    /// 
    /// A mutable reference to the data stored in the memory region.
    /// 
    /// # Example
    /// 
    /// ```no_run
    /// # use mprotect_rs::{UnsafeProtectedRegion, AccessRights, allocator::Mmap};
    /// # unsafe {
    /// let mut region = UnsafeProtectedRegion::<Mmap, i32>::new(AccessRights::READ_WRITE)?;
    /// *region.as_mut() = 42;
    /// # Ok::<(), mprotect_rs::MprotectError>(())
    /// # }
    /// ```
    pub unsafe fn as_mut(&mut self) -> &mut T {
        &mut *self.ptr.as_ptr()
    }

    /// Returns a reference to the data stored in the memory region.
    /// 
    /// # Safety
    /// 
    /// This function is unsafe because:
    /// - It assumes the memory has been properly initialized
    /// - The caller must respect the current access rights
    /// - Violating read permissions will cause a segmentation fault
    /// - The returned reference's lifetime is tied to the region
    /// 
    /// # Returns
    /// 
    /// A reference to the data stored in the memory region.
    /// 
    /// # Example
    /// 
    /// ```no_run
    /// # use mprotect_rs::{UnsafeProtectedRegion, AccessRights, allocator::Mmap};
    /// # unsafe {
    /// let region = UnsafeProtectedRegion::<Mmap, i32>::new(AccessRights::READ)?;
    /// let value = *region.as_ref();
    /// # Ok::<(), mprotect_rs::MprotectError>(())
    /// # }
    /// ```
    pub unsafe fn as_ref(&self) -> &T {
        &*self.ptr.as_ptr()
    }
}

impl<A: allocator::Allocator<T>, T> Drop for UnsafeProtectedRegion<A, T> {
    /// Automatically deallocates the memory region when dropped.
    /// 
    /// This destructor ensures proper cleanup by:
    /// - Calling the allocator's deallocation method
    /// - Releasing the memory back to the system
    /// 
    /// **Warning**: If deallocation fails, this method will panic. Deallocation failures
    /// are rare but can occur due to memory corruption or invalid memory regions.
    fn drop(&mut self) {
        let ret = unsafe { self.allocator.deallocate() };
        if let Err(e) = ret {
            panic!("Failed to deallocate memory: {:?}", e.to_string());
        }
    }
}
