mod pkey;
pub use pkey::*;

mod mprotect;
pub use mprotect::*;

mod safemem;
pub use safemem::*;

mod safeguard;
pub use safeguard::*;

mod pkeyguard;
pub use pkeyguard::*;

mod regionguard;
pub use regionguard::*;

pub type Errno = i32;

use std::fmt::Display;

#[derive(Debug)]
pub enum MprotectError {
    PkeyAllocFailed(Errno),
    MemoryAllocationFailed(Errno),
    MemoryDeallocationFailed(Errno),
    MprotectFailed(Errno),
    PkeyMprotectFailed(Errno),
    NoPkeyAssociated,
}

impl Display for MprotectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MprotectError::PkeyAllocFailed(errno) => write!(f, "pkey allocation failed with errno {}", errno),
            MprotectError::MemoryAllocationFailed(errno) => write!(f, "memory allocation failed with errno {}", errno),
            MprotectError::MemoryDeallocationFailed(errno) => write!(f, "memory deallocation failed with errno {}", errno),
            MprotectError::MprotectFailed(errno) => write!(f, "mprotect failed with errno {}", errno),
            MprotectError::PkeyMprotectFailed(errno) => write!(f, "pkey mprotect failed with errno {}", errno),
            MprotectError::NoPkeyAssociated => write!(f, "no protection key associated with the memory region"),
        }
    }
}
