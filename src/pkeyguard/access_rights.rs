use crate::mpk::PkeyAccessRights;
use crate::mprotect::access_rights::AccessRights;

/// Represents basic access control for memory protection keys.
///
/// Implementors define how a given access level maps to `PkeyAccessRights`.
pub trait Access { 
    fn new() -> Self;
    fn value(&self) -> RegionAccessRights;
}
/// Marker trait for types that permit read access.
pub trait CanRead: Access {}
/// Marker trait for types that permit write access.
pub trait CanWrite: Access {}

/// Access rights implementations for protection keys and PTE access control.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RegionAccessRights {
    pub pkey_rights: PkeyAccessRights,
    pub pte_rights: AccessRights,
}

/// Common access-level implementations.
pub mod permissions {
    pub use super::*;

    /// Denies all access.
    pub struct NoAccess;
    /// Grants read-only access.
    pub struct ReadOnly;
    /// Grants both read and write access.
    pub struct ReadWrite;
    /// Grants execute-only access.
    pub struct ExecuteOnly;
    /// Grants read and execute access.
    pub struct ReadExecute;
    /// Grants read, write, and execute access.
    pub struct ReadWriteExecute;

    impl Access for NoAccess {
        fn new() -> Self { NoAccess }
        fn value(&self) -> RegionAccessRights { RegionAccessRights { pkey_rights: PkeyAccessRights::DisableAccess, pte_rights: AccessRights::NONE } }
    }
    impl Access for ReadOnly {
        fn new() -> Self { ReadOnly }
        fn value(&self) -> RegionAccessRights { RegionAccessRights { pkey_rights: PkeyAccessRights::DisableWrite, pte_rights: AccessRights::READ } }
    }
    impl Access for ReadWrite {
        fn new() -> Self { ReadWrite }
        fn value(&self) -> RegionAccessRights { RegionAccessRights { pkey_rights: PkeyAccessRights::EnableAccessWrite, pte_rights: AccessRights::READ_WRITE } }
    }
    impl Access for ExecuteOnly {
        fn new() -> Self { ExecuteOnly }
        fn value(&self) -> RegionAccessRights { RegionAccessRights { pkey_rights: PkeyAccessRights::DisableAccess, pte_rights: AccessRights::EXEC } }
    }
    impl Access for ReadExecute {
        fn new() -> Self { ReadExecute }
        fn value(&self) -> RegionAccessRights { RegionAccessRights { pkey_rights: PkeyAccessRights::DisableWrite, pte_rights: AccessRights::READ_EXEC } }
    }
    impl Access for ReadWriteExecute {
        fn new() -> Self { ReadWriteExecute }
        fn value(&self) -> RegionAccessRights { RegionAccessRights { pkey_rights: PkeyAccessRights::EnableAccessWrite, pte_rights: AccessRights::READ_WRITE_EXEC } }
    }

    impl CanRead for ReadOnly {}
    impl CanRead for ReadWrite {}
    impl CanWrite for ReadWrite {}
}
