mod pkey;
pub use pkey::*;

mod mprotect;
pub use mprotect::*;

pub type Errno = i32;

#[derive(Debug)]
pub enum MprotectError {
    PkeyAllocFailed(Errno),
    MemoryAllocationFailed(Errno),
    MemoryDeallocationFailed(Errno),
    MprotectFailed(Errno),
    PkeyMprotectFailed(Errno),
    NoPkeyAssociated,
}

