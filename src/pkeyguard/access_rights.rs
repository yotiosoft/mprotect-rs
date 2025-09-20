pub trait Access {}
pub trait CanRead: Access {}
pub trait CanWrite: Access {}

pub struct ReadOnly;
pub struct ReadWrite;
pub struct NoAccess;

impl Access for ReadOnly {}
impl Access for ReadWrite {}
impl Access for NoAccess {}

impl CanRead for ReadOnly {}
impl CanRead for ReadWrite {}
impl CanWrite for ReadWrite {}
