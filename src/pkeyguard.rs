use crate::pkey::*;

use crate::mprotect::*;

struct PkeyGuard {
    pkey: PKey,
    default_access_rights: PkeyAccessRights,
}

impl PkeyGuard {
    pub fn new(default_access_rights: PkeyAccessRights) -> Result<Self, super::MprotectError> {
        let pkey = PKey::new(default_access_rights)?;
        Ok(
            PkeyGuard {
                pkey,
                default_access_rights,
            }
        )
    }
}
