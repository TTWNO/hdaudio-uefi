use core::cmp::PartialEq;
use core::ops::{BitAnd, BitOr, Not};


use core::ptr::{read_unaligned, write_unaligned};
use core::mem::MaybeUninit;

#[repr(packed)]
pub struct Mmio<T> {
    value: MaybeUninit<T>,
}

impl<T> Mmio<T> {
    /// Create a new Mmio without initializing
    #[deprecated = "unsound because it's possible to read even though it's uninitialized"]
    pub fn new() -> Self {
        unsafe { Self::uninit() }
    }
    pub unsafe fn zeroed() -> Self {
        Self {
            value: MaybeUninit::zeroed(),
        }
    }
    pub unsafe fn uninit() -> Self {
        Self {
            value: MaybeUninit::uninit(),
        }
    }
    pub const fn from(value: T) -> Self {
        Self {
            value: MaybeUninit::new(value),
        }
    }
}

impl<T> Io for Mmio<T> where T: Copy + PartialEq + BitAnd<Output = T> + BitOr<Output = T> + Not<Output = T> {
    type Value = T;

    fn read(&self) -> T {
        unsafe { 
          self.value.assume_init()
          //let ptr = self.value;
          //read_unaligned(ptr.as_ptr())
        }
    }

    fn write(&mut self, value: T) {
        unsafe { 
          *self = Mmio::from(value);
          //let mut v  = self.value;
          //write_unaligned(ptr.as_mut_ptr(), value)
        }
    }
}

pub trait Io {
    type Value: Copy + PartialEq + BitAnd<Output = Self::Value> + BitOr<Output = Self::Value> + Not<Output = Self::Value>;

    fn read(&self) -> Self::Value;
    fn write(&mut self, value: Self::Value);

    #[inline(always)]
    fn readf(&self, flags: Self::Value) -> bool  {
        (self.read() & flags) as Self::Value == flags
    }

    #[inline(always)]
    fn writef(&mut self, flags: Self::Value, value: bool) {
        let tmp: Self::Value = match value {
            true => self.read() | flags,
            false => self.read() & !flags,
        };
        self.write(tmp);
    }
}

pub struct ReadOnly<I: Io> {
    inner: I
}

impl<I: Io> ReadOnly<I> {
    pub const fn new(inner: I) -> ReadOnly<I> {
        ReadOnly {
            inner: inner
        }
    }

    #[inline(always)]
    pub fn read(&self) -> I::Value {
        self.inner.read()
    }

    #[inline(always)]
    pub fn readf(&self, flags: I::Value) -> bool {
        self.inner.readf(flags)
    }
}

pub struct WriteOnly<I: Io> {
    inner: I
}

impl<I: Io> WriteOnly<I> {
    pub const fn new(inner: I) -> WriteOnly<I> {
        WriteOnly {
            inner: inner
        }
    }

    #[inline(always)]
    pub fn write(&mut self, value: I::Value) {
        self.inner.write(value)
    }

    #[inline(always)]
    pub fn writef(&mut self, flags: I::Value, value: bool) {
        self.inner.writef(flags, value)
    }
}
