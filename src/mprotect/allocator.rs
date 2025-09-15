use libc;

mod mmap;

#[repr(i32)]
pub enum AllocatorError {
    MmapFailed(i32),
    MunmapFailed(i32),
}

pub struct MemoryRegion<T> {
    ptr: *mut T,
    len: usize,
}

pub trait Allocator<T> {
    fn allocate(size: usize, prot: i32) -> Result<MemoryRegion<T>, AllocatorError>;
    fn deallocate(ptr: *mut libc::c_void, size: usize) -> Result<(), AllocatorError>;
}
