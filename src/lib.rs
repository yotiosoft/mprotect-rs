use libc;

pub type Errno = i32;

pub enum MprotectError {
    AllocFailed(Errno),
}

#[repr(i32)]
pub enum PkeyAccessRights {
    DisableAccess = 0x1,
    DisableWrite = 0x2,
}

#[repr(i32)]
pub enum AccessRights {
    None = libc::PROT_NONE,
    Read = libc::PROT_READ,
    Write = libc::PROT_WRITE,
    Exec = libc::PROT_EXEC,
    ReadWrite = libc::PROT_READ | libc::PROT_WRITE,
    ReadExec = libc::PROT_READ | libc::PROT_EXEC,
    WriteExec = libc::PROT_WRITE | libc::PROT_EXEC,
    ReadWriteExec = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
}

pub struct ProtectionKey {
    key: u32,
}
impl ProtectionKey {
    pub fn new(access: PkeyAccessRights) -> Result<Self, MprotectError> {
        let key = unsafe {
            libc::syscall(
                libc::SYS_pkey_alloc,
                0,                  // Flags. According to the man page, this is reserved for future use and currently must be 0.
                access,             // Initial access rights
            )
        };

        if key < 0 {
            let err_no = std::io::Error::last_os_error().raw_os_error().unwrap();
            Err(MprotectError::AllocFailed(err_no))
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
