use crate::pkey::PkeyAccessRights;

/// Represents basic access control for memory protection keys.
///
/// Implementors define how a given access level maps to `PkeyAccessRights`.
pub trait Access { 
    fn new() -> Self;
    fn value(&self) -> PkeyAccessRights; 
}
/// Marker trait for types that permit read access.
pub trait CanRead: Access {}
/// Marker trait for types that permit write access.
pub trait CanWrite: Access {}

/// Common access-level implementations.
pub mod permissions {
    pub use super::*;

    /// Grants read-only access.
    pub struct ReadOnly;
    /// Grants both read and write access.
    pub struct ReadWrite;
    /// Denies all access.
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
