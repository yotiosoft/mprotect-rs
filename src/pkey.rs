use libc;
use std::fmt::Display;

mod pkru;

/// Access rights for a protection key.
/// These rights determine the access permissions for memory regions associated with the protection key.
/// - `EnableAccessWrite`: Both read and write access are enabled.
/// - `DisableAccess`: Both read and write access are disabled.
/// - `DisableWrite`: Write access is disabled, but read access is enabled.
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

/// A protection key (pkey) that can be associated with memory regions to control access rights.
/// Protection keys allow for fine-grained control over memory access permissions, enabling or disabling
/// read and write access to memory regions associated with the key.
/// These keys are allocated by ``new()`` and automatically freed when the `PKey` instance is dropped.
#[derive(Clone)]
pub struct PKey {
    key: u32,
}
impl PKey {
    /// Allocates a new protection key with the specified access rights.
    /// # Arguments
    /// - `access`: The initial access rights for the protection key.
    /// # Returns
    /// - `Ok(PKey)`: A new `PKey` instance if allocation
    /// succeeds.
    /// - `Err(MprotectError)`: An error if allocation fails.
    pub fn new(access: PkeyAccessRights) -> Result<Self, super::MprotectError> {
        let key = unsafe {
            libc::syscall(
                libc::SYS_pkey_alloc,
                0,                  // Flags. According to the man page, this is reserved for future use and currently must be 0.
                access,             // Initial access rights
            )
        };

        if key < 0 {
            let err_no = std::io::Error::last_os_error().raw_os_error().unwrap();
            Err(super::MprotectError::PkeyAllocFailed(err_no))
        } else {
            Ok(PKey { key: key as u32 })
        }
    }

    /// Retrieves the current access rights of the protection key.
    /// This method reads the PKRU register to determine the access rights associated with the key.
    /// # Returns
    /// - The current access rights of the protection key.
    pub fn get_access_rights(&self) -> PkeyAccessRights {
        let pkru_value = unsafe {
            pkru::rdpkru()
        };
        let rights_bits = (pkru_value >> (self.key * 2)) & 0b11;
        match rights_bits {
            0b00 => PkeyAccessRights::EnableAccessWrite,
            0b01 => PkeyAccessRights::DisableAccess,
            0b10 => PkeyAccessRights::DisableWrite,
            0b11 => PkeyAccessRights::DisableAccess,
            _ => { unreachable!() }
        }
    }

    /// Sets the access rights of the protection key.
    /// This method modifies the PKRU register to update the access rights associated with the key.
    /// # Arguments
    /// - `access`: The new access rights to be set for the protection key.
    /// # Returns
    /// - `Ok(())`: If the access rights are successfully updated.
    /// - `Err(MprotectError)`: If there is an error updating the access rights.
    pub fn set_access_rights(&self, access: PkeyAccessRights) -> Result<(), super::MprotectError> {
        let pkru_value = unsafe {
            pkru::rdpkru()
        };
        let new_pkru_bits = match access {
            PkeyAccessRights::EnableAccessWrite => 0b00,
            PkeyAccessRights::DisableAccess => 0b01,
            PkeyAccessRights::DisableWrite => 0b10,
        } << (self.key * 2);
        let new_pkru_value = pkru_value & !(0b11 << (self.key * 2)) | new_pkru_bits;
        unsafe {
            pkru::wrpkru(new_pkru_value);
        }
        Ok(())
    }

    /// Returns the protection key ID.
    /// # Returns
    /// - The protection key ID as a `u32`.
    pub fn key(&self) -> u32 {
        self.key
    }
}

impl Drop for PKey {
    /// Automatically frees the protection key when the `PKey` instance is dropped.
    /// This ensures that the protection key is properly released and can be reused by the system.
    /// If freeing the key fails, it silently ignores the error as there is no way to handle it in a destructor.
    fn drop(&mut self) {
        unsafe {
            libc::syscall(
                libc::SYS_pkey_free,
                self.key,           // The protection key to be freed
            );
        }
    }
}
