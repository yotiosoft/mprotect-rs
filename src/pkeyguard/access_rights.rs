use crate::pkey::PkeyAccessRights;

pub trait Access { 
    fn new() -> Self;
    fn value(&self) -> PkeyAccessRights; 
}
pub trait CanRead: Access {}
pub trait CanWrite: Access {}

pub mod permissions {
    pub use super::*;

    pub struct ReadOnly;
    pub struct ReadWrite;
    pub struct NoAccess;

    impl Access for ReadOnly {
        fn new() -> Self { ReadOnly }
        fn value(&self) -> PkeyAccessRights { PkeyAccessRights::DisableWrite }
    }
    impl Access for ReadWrite {
        fn new() -> Self { ReadWrite }
        fn value(&self) -> PkeyAccessRights { PkeyAccessRights::EnableAccessWrite }
    }
    impl Access for NoAccess {
        fn new() -> Self { NoAccess }
        fn value(&self) -> PkeyAccessRights { PkeyAccessRights::DisableAccess }
    }

    impl CanRead for ReadOnly {}
    impl CanRead for ReadWrite {}
    impl CanWrite for ReadWrite {}
}
