use libc;
use std::fmt::Display;
use std::ptr::NonNull;

mod mmap;
pub use mmap::Mmap;

mod jmalloc;
pub use jmalloc::Jmalloc;

#[repr(i32)]
pub enum AllocatorError {
    MmapFailed(i32),
    MunmapFailed(i32),
    LayoutError,
}

impl Display for AllocatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AllocatorError::MmapFailed(errno) => write!(f, "mmap failed with errno {}", errno),
            AllocatorError::MunmapFailed(errno) => write!(f, "munmap failed with errno {}", errno),
            AllocatorError::LayoutError => write!(f, "layout error"),
        }
    }
}

pub struct MemoryRegion<A: Allocator<T>, T> {
    ptr: NonNull<T>,
    len: usize,
    allocator: A,
}

pub trait Allocator<T> {
    unsafe fn allocator_alloc(prot: &i32) -> Result<MemoryRegion<Self, T>, AllocatorError>
    where
        Self: Sized;

    unsafe fn allocator_dealloc(&self) -> Result<(), AllocatorError>;
}

impl<A: Allocator<T>, T> MemoryRegion<A, T> {
    pub unsafe fn allocate(access_rights: &super::AccessRights) -> Result<Self, AllocatorError> {
        let access_rights = access_rights.to_i32();
        A::allocator_alloc(&access_rights)
    }
    pub unsafe fn deallocate(&self) -> Result<(), AllocatorError> {
        self.allocator.allocator_dealloc()
    }
    pub fn ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }
    pub fn len(&self) -> usize {
        self.len
    }
}
