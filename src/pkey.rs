use libc;

mod pkru;

#[repr(i32)]
pub enum PkeyAccessRights {
    EnableAccessWrite = 0x0,
    DisableAccess = 0x1,
    DisableWrite = 0x2,
}

pub struct ProtectionKey {
    key: u32,
}
impl ProtectionKey {
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
            Ok(ProtectionKey { key: key as u32 })
        }
    }

    pub fn get_access_rights(&self) -> Result<PkeyAccessRights, super::MprotectError> {
        let pkru_value = unsafe {
            pkru::rdpkru()
        };
        let rights_bits = (pkru_value >> (self.key * 2)) & 0b11;
        match rights_bits {
            0b00 => Ok(PkeyAccessRights::EnableAccessWrite),
            0b01 => Ok(PkeyAccessRights::DisableAccess),
            0b10 => Ok(PkeyAccessRights::DisableWrite),
            0b11 => Ok(PkeyAccessRights::DisableAccess),
            _ => { unreachable!() }
        }
    }

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

    pub fn key(&self) -> u32 {
        self.key
    }
}

impl Drop for ProtectionKey {
    fn drop(&mut self) {
        unsafe {
            libc::syscall(
                libc::SYS_pkey_free,
                self.key,           // The protection key to be freed
            );
        }
    }
}
