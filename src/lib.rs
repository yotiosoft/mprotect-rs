mod pkey;
pub use pkey::*;

mod mprotect;
pub use mprotect::*;

pub type Errno = i32;

pub enum MprotectError {
    PkeyAllocFailed(Errno),
    MemoryAllocationFailed(Errno),
}

