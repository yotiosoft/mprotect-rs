use libc;

#[repr(i32)]
pub enum PkeyAccessRights {
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
