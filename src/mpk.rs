use std::fmt::Display;

mod pkru;

use crate::AccessRights;
use crate::allocator;
use crate::UnsafeProtectedRegion;

/// Access rights for a protection key.
/// 
/// These rights determine the access permissions for memory regions associated with the protection key.
/// The rights are enforced by the CPU's Protection Key Rights for User pages (PKRU) register.
/// 
/// # Variants
/// 
/// - `EnableAccessWrite`: Both read and write access are enabled (bits: 00).
/// - `DisableAccess`: Both read and write access are disabled (bits: 01).
/// - `DisableWrite`: Write access is disabled, but read access is enabled (bits: 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum PkeyAccessRights {
    EnableAccessWrite = 0x0,
    DisableAccess = 0x1,
    DisableWrite = 0x2,
}

impl Display for PkeyAccessRights {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PkeyAccessRights::EnableAccessWrite => write!(f, "Enable Access and Write"),
            PkeyAccessRights::DisableAccess => write!(f, "Disable Access"),
            PkeyAccessRights::DisableWrite => write!(f, "Disable Write"),
        }
    }
}

/// A protection key (pkey) for fine-grained memory access control.
/// 
/// Protection keys provide hardware-based memory protection that allows thread-local
/// control over memory access permissions. They work in conjunction with page-level
/// permissions to provide an additional layer of security.
/// 
/// Protection keys are a limited resource (typically 15 keys available on x86-64).
/// Keys are allocated by `new()` and automatically freed when the `PKey` instance is dropped.
/// 
/// # How Protection Keys Work
/// 
/// 1. A memory region is associated with a protection key using `pkey_mprotect`
/// 2. The PKRU register controls thread-local access rights for each key
/// 3. The most restrictive permission between page-level and key-level applies
/// 
/// # Example
/// 
/// ```no_run
/// use mprotect_rs::{PKey, PkeyAccessRights, UnsafeProtectedRegion, AccessRights, allocator::Mmap};
/// 
/// unsafe {
///     // Allocate a protection key
///     let pkey = PKey::new(PkeyAccessRights::DisableAccess)?;
///     
///     // Create a memory region
///     let region = UnsafeProtectedRegion::<Mmap, i32>::new(AccessRights::READ_WRITE)?;
///     
///     // Associate the region with the protection key
///     pkey.associate(&region, AccessRights::READ_WRITE)?;
///     
///     // Now access is controlled by the pkey's access rights
///     pkey.set_access_rights(PkeyAccessRights::EnableAccessWrite)?;
///     // Memory is now accessible
/// }
/// # Ok::<(), mprotect_rs::MprotectError>(())
/// ```
#[derive(Clone)]
pub struct PKey {
    key: u32,
}

impl PKey {
    /// Allocates a new protection key with the specified initial access rights.
    /// 
    /// This method allocates a protection key using the `pkey_alloc` system call.
    /// Protection keys are a limited resource (typically 15 keys available on x86-64),
    /// and must be explicitly freed when no longer needed (handled automatically by `Drop`).
    /// 
    /// # Safety
    /// 
    /// This function is unsafe because it directly interacts with system calls and
    /// modifies memory protection state.
    /// 
    /// # Arguments
    /// 
    /// - `access`: The initial access rights for the protection key. This determines
    ///   the default permissions for memory regions associated with this key.
    /// 
    /// # Returns
    /// 
    /// - `Ok(PKey)`: A new `PKey` instance if allocation succeeds.
    /// - `Err(MprotectError::PkeyAllocFailed)`: If the system does not support protection keys,
    ///   all keys are already allocated, or invalid parameters were provided.
    /// 
    /// # Example
    /// 
    /// ```no_run
    /// use mprotect_rs::{PKey, PkeyAccessRights};
    /// 
    /// unsafe {
    ///     let pkey = PKey::new(PkeyAccessRights::DisableAccess)?;
    ///     // Use the protection key...
    /// }
    /// # Ok::<(), mprotect_rs::MprotectError>(())
    /// ```
    pub unsafe fn new(access: PkeyAccessRights) -> Result<Self, super::MprotectError> {
        let key = libc::syscall(
            libc::SYS_pkey_alloc,
            0,                  // Flags. According to the man page, this is reserved for future use and currently must be 0.
            access,             // Initial access rights
        );

        if key < 0 {
            let err_no = std::io::Error::last_os_error().raw_os_error().unwrap();
            Err(super::MprotectError::PkeyAllocFailed(err_no))
        } else {
            Ok(PKey { key: key as u32 })
        }
    }

    /// Retrieves the current access rights of the protection key from the PKRU register.
    /// 
    /// This method reads the current state of the Protection Key Rights for User pages (PKRU)
    /// register to determine the access rights associated with this protection key.
    /// The PKRU register controls per-thread access permissions for memory regions
    /// associated with protection keys.
    /// 
    /// # Safety
    /// 
    /// This function is unsafe because it reads CPU registers directly and the returned
    /// value may change if another thread modifies the PKRU register.
    /// 
    /// # Returns
    /// 
    /// The current access rights of the protection key as a `PkeyAccessRights` enum value.
    /// 
    /// # Example
    /// 
    /// ```no_run
    /// # use mprotect_rs::{PKey, PkeyAccessRights};
    /// # unsafe {
    /// let pkey = PKey::new(PkeyAccessRights::DisableAccess)?;
    /// let rights = pkey.get_access_rights();
    /// assert_eq!(rights, PkeyAccessRights::DisableAccess);
    /// # Ok::<(), mprotect_rs::MprotectError>(())
    /// # }
    /// ```
    pub unsafe fn get_access_rights(&self) -> PkeyAccessRights {
        let pkru_value = pkru::rdpkru();

        let rights_bits = (pkru_value >> (self.key * 2)) & 0b11;
        match rights_bits {
            0b00 => PkeyAccessRights::EnableAccessWrite,
            0b01 => PkeyAccessRights::DisableAccess,
            0b10 => PkeyAccessRights::DisableWrite,
            0b11 => PkeyAccessRights::DisableAccess,
            _ => { unreachable!() }
        }
    }

    /// Sets the access rights of the protection key by modifying the PKRU register.
    /// 
    /// This method updates the Protection Key Rights for User pages (PKRU) register
    /// to change the access permissions for memory regions associated with this protection key.
    /// The change takes effect immediately and applies to all memory regions associated
    /// with this key in the current thread.
    /// 
    /// **Note**: PKRU is a thread-local register, so changes only affect the current thread.
    /// 
    /// # Safety
    /// 
    /// This function is unsafe because it directly modifies CPU registers and can affect
    /// the accessibility of memory regions across the program.
    /// 
    /// # Arguments
    /// 
    /// - `access`: The new access rights to be set for the protection key.
    /// 
    /// # Returns
    /// 
    /// - `Ok(())`: If the access rights are successfully updated.
    /// - `Err(MprotectError)`: Currently always returns `Ok`, but the signature allows
    ///   for future error handling.
    /// 
    /// # Example
    /// 
    /// ```no_run
    /// # use mprotect_rs::{PKey, PkeyAccessRights};
    /// # unsafe {
    /// let pkey = PKey::new(PkeyAccessRights::EnableAccessWrite)?;
    /// // Later, disable write access
    /// pkey.set_access_rights(PkeyAccessRights::DisableWrite)?;
    /// # Ok::<(), mprotect_rs::MprotectError>(())
    /// # }
    /// ```
    pub unsafe fn set_access_rights(&self, access: PkeyAccessRights) -> Result<(), super::MprotectError> {
        let pkru_value = pkru::rdpkru();

        let new_pkru_bits = match access {
            PkeyAccessRights::EnableAccessWrite => 0b00,
            PkeyAccessRights::DisableAccess => 0b01,
            PkeyAccessRights::DisableWrite => 0b10,
        } << (self.key * 2);
        
        let new_pkru_value = pkru_value & !(0b11 << (self.key * 2)) | new_pkru_bits;
        pkru::wrpkru(new_pkru_value);
        
        Ok(())
    }

    /// Returns the protection key ID.
    /// 
    /// The protection key ID is a numeric identifier assigned by the kernel when the key
    /// is allocated. This ID can be used with low-level system calls if needed.
    /// 
    /// # Returns
    /// 
    /// The protection key ID as a `u32` value (typically in the range 0-15 on x86-64).
    pub fn key(&self) -> u32 {
        self.key
    }

    /// Internal implementation of `pkey_mprotect` system call.
    /// 
    /// This is a private helper method that performs the actual `pkey_mprotect` system call
    /// to associate a protection key with a memory region and set its page-level permissions.
    /// 
    /// # Safety
    /// 
    /// This function is unsafe because it:
    /// - Directly invokes system calls
    /// - Modifies memory protection state
    /// - Requires valid memory addresses and sizes
    /// 
    /// # Arguments
    /// 
    /// - `access_rights`: The page-level access rights to be set using `pkey_mprotect`.
    /// - `ptr`: Pointer to the start of the memory region.
    /// - `len`: Length of the memory region in bytes.
    /// - `pkey_id`: The protection key ID to associate with the memory region.
    /// 
    /// # Returns
    /// 
    /// - `Ok(())`: On successful association.
    /// - `Err(MprotectError::PkeyMprotectFailed)`: If the system call fails.
    unsafe fn impl_pkey_mprotect(access_rights: AccessRights, ptr: *mut libc::c_void, len: usize, pkey_id: u32) -> Result<(), super::MprotectError> {
        let ret = libc::syscall(
            libc::SYS_pkey_mprotect,
            ptr,
            len,
            access_rights.to_i32(),
            pkey_id
        );

        if ret != 0 {
            let err_no = std::io::Error::last_os_error().raw_os_error().unwrap();
            return Err(super::MprotectError::PkeyMprotectFailed(err_no));
        }

        Ok(())
    }

    /// Associates this protection key with a memory region and sets its page-level access rights.
    /// 
    /// This method uses the `pkey_mprotect` system call to associate the protection key
    /// with the specified memory region and set the page-level permissions in the page table entries.
    /// After association, the region's accessibility is controlled by both:
    /// 1. Page-level permissions (set by this method)
    /// 2. Protection key permissions (controlled via PKRU register)
    /// 
    /// The most restrictive permission applies.
    /// 
    /// # Safety
    /// 
    /// This function is unsafe because it:
    /// - Modifies memory protection state
    /// - Requires the memory region to be valid and properly aligned
    /// - Can affect program behavior if misused
    /// 
    /// # Arguments
    /// 
    /// - `region`: A reference to the memory region to be associated with this protection key.
    /// - `access_rights`: The page-level access rights to be set for the memory region.
    /// 
    /// # Returns
    /// 
    /// - `Ok(())`: On successful association and permission change.
    /// - `Err(MprotectError::PkeyMprotectFailed)`: If the `pkey_mprotect` system call fails.
    /// 
    /// # Example
    /// 
    /// ```no_run
    /// # use mprotect_rs::{PKey, PkeyAccessRights, UnsafeProtectedRegion, AccessRights, allocator::Mmap};
    /// # unsafe {
    /// let pkey = PKey::new(PkeyAccessRights::DisableWrite)?;
    /// let region = UnsafeProtectedRegion::<Mmap, i32>::new(AccessRights::READ_WRITE)?;
    /// pkey.associate(&region, AccessRights::READ_WRITE)?;
    /// # Ok::<(), mprotect_rs::MprotectError>(())
    /// # }
    /// ```
    pub unsafe fn associate<A: allocator::Allocator<T>, T>(&self, region: &UnsafeProtectedRegion<A, T>, access_rights: AccessRights) -> Result<(), super::MprotectError> {
        Self::impl_pkey_mprotect(access_rights, region.ptr() as *mut libc::c_void, region.len(), self.key)?;
        Ok(())
    }

    /// Disassociates the memory region from this protection key by resetting to the default key.
    /// 
    /// This method resets the memory region's association to the default protection key (key 0),
    /// which is always enabled and cannot be disabled. This effectively removes protection
    /// key-based access control from the region, leaving only the page-level permissions.
    /// 
    /// # Safety
    /// 
    /// This function is unsafe because it:
    /// - Modifies memory protection state
    /// - Requires the memory region to be valid and properly aligned
    /// 
    /// # Arguments
    /// 
    /// - `region`: A reference to the memory region to be disassociated from this protection key.
    /// - `access_rights`: The page-level access rights to be set for the memory region.
    /// 
    /// # Returns
    /// 
    /// - `Ok(())`: On successful disassociation.
    /// - `Err(MprotectError::PkeyMprotectFailed)`: If the `pkey_mprotect` system call fails.
    /// 
    /// # Example
    /// 
    /// ```no_run
    /// # use mprotect_rs::{PKey, PkeyAccessRights, UnsafeProtectedRegion, AccessRights, allocator::Mmap};
    /// # unsafe {
    /// let pkey = PKey::new(PkeyAccessRights::DisableWrite)?;
    /// let region = UnsafeProtectedRegion::<Mmap, i32>::new(AccessRights::READ_WRITE)?;
    /// pkey.associate(&region, AccessRights::READ_WRITE)?;
    /// // Later, remove the protection key association
    /// pkey.disassociate(&region, AccessRights::READ_WRITE)?;
    /// # Ok::<(), mprotect_rs::MprotectError>(())
    /// # }
    /// ```
    pub unsafe fn disassociate<A: allocator::Allocator<T>, T>(&self, region: &UnsafeProtectedRegion<A, T>, access_rights: AccessRights) -> Result<(), super::MprotectError> {
        Self::impl_pkey_mprotect(access_rights, region.ptr() as *mut libc::c_void, region.len(), 0)?;
        Ok(())
    }
}

impl Drop for PKey {
    /// Automatically frees the protection key when the `PKey` instance is dropped.
    /// 
    /// This destructor ensures that the protection key is properly released back to the system
    /// using the `pkey_free` system call. After the key is freed, it can be reallocated
    /// by other parts of the program or by other processes.
    /// 
    /// **Note**: If freeing the key fails, the error is silently ignored as there is no
    /// safe way to handle errors in a destructor. However, failures are rare and typically
    /// only occur with invalid key IDs.
    fn drop(&mut self) {
        unsafe {
            libc::syscall(
                libc::SYS_pkey_free,
                self.key,           // The protection key to be freed
            );
        }
    }
}
