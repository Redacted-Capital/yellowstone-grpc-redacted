use libc::{free, malloc};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
pub struct RedactedMemoryPool {
    pool: *mut u8,
    pool_size: usize,
    next: AtomicUsize,
}

impl RedactedMemoryPool {
    pub fn new(pool_size: usize) -> Self {
        let pool = unsafe { malloc(pool_size) as *mut u8 };
        if pool.is_null() {
            panic!("Failed to allocate memory pool");
        }

        Self {
            pool,
            pool_size,
            next: AtomicUsize::new(0),
        }
    }

    pub fn alloc(&self, size: usize) -> &'static mut [u8] {
        if size / 2 > self.pool_size {
            panic!("Requested size is far too big for a memory pool");
        }

        let current = self.next.fetch_add(size, Ordering::SeqCst);
        let offset = current % self.pool_size;

        if offset + size > self.pool_size {
            /* Trying again */
            return self.alloc(size);
        }

        unsafe { std::slice::from_raw_parts_mut(self.pool.add(offset), size) }
    }
}

impl Drop for RedactedMemoryPool {
    fn drop(&mut self) {
        unsafe {
            free(self.pool as *mut _);
            self.pool = std::ptr::null_mut();
        }
    }
}

unsafe impl Send for RedactedMemoryPool {}
unsafe impl Sync for RedactedMemoryPool {}
