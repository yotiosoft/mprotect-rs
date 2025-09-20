use bitflags::bitflags;

bitflags! {
    /// Memory protection flags represented as bitflags.
    /// These correspond to the Page Table Entry (PTE) flags.
    /// - `NONE`: No access.
    /// - `READ`: Read-only access.
    /// - `WRITE`: Write-only access.
    /// - `EXEC`: Execute-only access.
    /// - `READ_WRITE`: Read and write access.
    /// - `READ_EXEC`: Read and execute access.
    /// - `WRITE_EXEC`: Write and execute access.
    /// - `READ_WRITE_EXEC`: Read, write, and execute access.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AccessRights: i32 {
        const NONE = libc::PROT_NONE;
        const READ = libc::PROT_READ;
        const WRITE = libc::PROT_WRITE;
        const EXEC = libc::PROT_EXEC;
        const READ_WRITE = libc::PROT_READ | libc::PROT_WRITE;
        const READ_EXEC = libc::PROT_READ | libc::PROT_EXEC;
        const WRITE_EXEC = libc::PROT_WRITE | libc::PROT_EXEC;
        const READ_WRITE_EXEC = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
    }
}

impl AccessRights {
    /// Add the specified access right to the current access rights.
    /// # Arguments
    /// - `right`: The access right to add.
    /// # Returns
    /// - The new access rights with the specified access right added.
    pub fn add(&self, right: AccessRights) -> AccessRights {
        AccessRights::from_bits_truncate(self.bits() | right.bits())
    }

    /// Removes the specified access right from the current access rights.
    /// # Arguments
    /// - `right`: The access right to remove.
    /// # Returns
    /// - The new access rights with the specified access right deleted.
    pub fn minus(&self, right: AccessRights) -> AccessRights {
        AccessRights::from_bits_truncate(self.bits() & !right.bits())
    }

    /// Checks if the current access rights contain the specified access right.
    /// # Arguments
    /// - `right`: The access right to check for.
    /// # Returns
    /// - `true`: If the current access rights contain the specified access right.
    /// - `false`: Otherwise.
    pub fn has(&self, right: AccessRights) -> bool {
        self.bits() & right.bits() == right.bits()
    }

    /// Convert the access rights to an i32 representation.
    /// # Returns
    /// - The i32 representation of the access rights.
    pub fn to_i32(&self) -> i32 {
        self.bits()
    }
}

pub mod access_permissions {
    use super::AccessRights;

    pub use read_allowed as ReadAllowed;
    pub use write_allowed as WriteAllowed;
    pub use execute_allowed as ExecuteAllowed;
    pub use no_access as NoAccessAllowed;
    pub use all_accesses as AllAccesses;

    #[derive(Copy, Clone)]
    pub struct NoAccess;
    #[derive(Copy, Clone)]
    pub struct ReadOnly;
    #[derive(Copy, Clone)]
    pub struct WriteOnly;
    #[derive(Copy, Clone)]
    pub struct ExecuteOnly;
    #[derive(Copy, Clone)]
    pub struct ReadWrite;
    #[derive(Copy, Clone)]
    pub struct ReadExecute;
    #[derive(Copy, Clone)]
    pub struct WriteExecute;
    #[derive(Copy, Clone)]
    pub struct ReadWriteExecute;

    pub trait AccessPermission {
        fn value(&self) -> AccessRights; 
    }

    impl AccessPermission for NoAccess {  fn value(&self) -> AccessRights { AccessRights::NONE } }
    impl AccessPermission for ReadOnly { fn value(&self) -> AccessRights { AccessRights::READ } }
    impl AccessPermission for WriteOnly { fn value(&self) -> AccessRights { AccessRights::WRITE } }
    impl AccessPermission for ExecuteOnly { fn value(&self) -> AccessRights { AccessRights::EXEC } }
    impl AccessPermission for ReadWrite { fn value(&self) -> AccessRights { AccessRights::READ_WRITE } }
    impl AccessPermission for ReadExecute { fn value(&self) -> AccessRights { AccessRights::READ_EXEC } }
    impl AccessPermission for WriteExecute { fn value(&self) -> AccessRights { AccessRights::WRITE_EXEC } }
    impl AccessPermission for ReadWriteExecute { fn value(&self) -> AccessRights { AccessRights::READ_WRITE_EXEC } }

    pub trait ReadAllowedTrait: AccessPermission {}
    pub mod read_allowed {
        pub use super::*;
        impl ReadAllowedTrait for ReadOnly {}
        impl ReadAllowedTrait for ReadWrite {}
        impl ReadAllowedTrait for ReadExecute {}
        impl ReadAllowedTrait for ReadWriteExecute {}
    }

    pub trait WriteAllowedTrait: AccessPermission {}
    pub mod write_allowed {
        pub use super::*;
        impl WriteAllowedTrait for WriteOnly {}
        impl WriteAllowedTrait for ReadWrite {}
        impl WriteAllowedTrait for WriteExecute {}
        impl WriteAllowedTrait for ReadWriteExecute {}
    }

    pub trait ExecuteAllowedTrait: AccessPermission {}
    pub mod execute_allowed {
        pub use super::*;
        impl ExecuteAllowedTrait for ExecuteOnly {}
        impl ExecuteAllowedTrait for ReadExecute {}
        impl ExecuteAllowedTrait for WriteExecute {}
        impl ExecuteAllowedTrait for ReadWriteExecute {}
    }

    pub trait NoAccessAllowedTrait: AccessPermission {}
    pub mod no_access {
        pub use super::*;
        impl NoAccessAllowedTrait for NoAccess {}
    }

    pub trait AllAccessesTrait { fn value(&self) -> AccessRights; }
    pub mod all_accesses {
        pub use super::*;
        impl AllAccessesTrait for NoAccess { fn value(&self) -> AccessRights { AccessRights::NONE } }
        impl AllAccessesTrait for ReadOnly { fn value(&self) -> AccessRights { AccessRights::READ } }
        impl AllAccessesTrait for WriteOnly { fn value(&self) -> AccessRights { AccessRights::WRITE } }
        impl AllAccessesTrait for ExecuteOnly { fn value(&self) -> AccessRights { AccessRights::EXEC } }
        impl AllAccessesTrait for ReadWrite { fn value(&self) -> AccessRights { AccessRights::READ_WRITE } }
        impl AllAccessesTrait for ReadExecute { fn value(&self) -> AccessRights { AccessRights::READ_EXEC } }
        impl AllAccessesTrait for WriteExecute { fn value(&self) -> AccessRights { AccessRights::WRITE_EXEC } }
        impl AllAccessesTrait for ReadWriteExecute { fn value(&self) -> AccessRights { AccessRights::READ_WRITE_EXEC } }
    }
}
