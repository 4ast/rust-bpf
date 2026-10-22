// SPDX-License-Identifier: GPL-2.0
//! core: mem, ptr, cell, MaybeUninit, layout.
#![no_std]
#![no_main]
use core::cell::{Cell, OnceCell, RefCell, UnsafeCell};
use core::mem::{self, ManuallyDrop, MaybeUninit};
use core::ptr::{self, NonNull};
use rt::{bb, check, check_eq, test};

test!(mem_swap_replace_take, {
    let (mut a, mut b) = (bb(1u64), bb(2u64));
    mem::swap(&mut a, &mut b);
    check!(a == 2 && b == 1);
    check_eq!(mem::replace(&mut a, 9), 2);
    check_eq!(mem::take(&mut a), 9);
    check_eq!(a, 0);
    let mut x = bb([1u64; 16]);
    let mut y = bb([2u64; 16]);
    mem::swap(&mut x, &mut y);
    check!(x[15] == 2 && y[0] == 1);
    let mut s = bb("abc");
    check_eq!(mem::take(&mut s), "abc");
    check_eq!(s, "");
    let mut o = bb(Some(3));
    check_eq!(mem::replace(&mut o, None), Some(3));
});

#[repr(C)]
struct Mixed {
    a: u8,
    b: u64,
    c: u16,
}
#[repr(C, packed)]
struct Packed {
    a: u8,
    b: u64,
    c: u16,
}
#[repr(align(64))]
struct Aligned(u8);
#[repr(C)]
union Bits {
    f: [u8; 8],
    u: u64,
}

test!(mem_layout, {
    check_eq!(mem::size_of::<Mixed>(), 24);
    check_eq!(mem::align_of::<Mixed>(), 8);
    check_eq!(mem::offset_of!(Mixed, c), 16);
    check_eq!(mem::size_of::<Packed>(), 11);
    check_eq!(mem::align_of::<Packed>(), 1);
    check_eq!(mem::size_of::<Aligned>(), 64);
    check_eq!(mem::size_of::<u128>(), 16);
    check_eq!(mem::align_of::<u128>(), 16);
    check_eq!(mem::size_of::<&str>(), 16);
    check_eq!(mem::size_of::<Option<NonNull<u8>>>(), 8);
    check_eq!(mem::size_of::<()>(), 0);
    check_eq!(mem::size_of_val(bb(&[0u16; 5][..])), 10);
    check_eq!(mem::size_of_val(bb("héllo")), 6);
    check!(mem::needs_drop::<Guard>() && !mem::needs_drop::<u8>());
});

test!(mem_packed_unaligned, {
    let p = bb(Packed { a: 1, b: 0x1122334455667788, c: 0x99aa });
    let (b, c) = (p.b, p.c);
    check!(p.a == 1 && b == 0x1122334455667788 && c == 0x99aa);
    let buf = bb([0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    let v = unsafe { ptr::read_unaligned(buf.as_ptr().add(1) as *const u64) };
    check_eq!(v, 0x0807060504030201);
    let mut out = bb([0u8; 10]);
    unsafe { ptr::write_unaligned(out.as_mut_ptr().add(3) as *mut u32, 0xaabbccdd) };
    check_eq!(out, [0, 0, 0, 0xdd, 0xcc, 0xbb, 0xaa, 0, 0, 0]);
});

test!(mem_align_of_locals, {
    let a = Aligned(bb(7));
    let b = bb(1u128);
    let c = bb([0u8; 3]);
    check_eq!(&a as *const _ as usize % 16, 0);
    check_eq!(&b as *const _ as usize % 16, 0);
    check!(a.0 == 7 && c[2] == 0);
});

test!(mem_union_transmute, {
    let u = Bits { u: bb(0x0102030405060708) };
    check_eq!(unsafe { u.f }, [8, 7, 6, 5, 4, 3, 2, 1]);
    let v: u32 = unsafe { mem::transmute(bb([1u8, 0, 0, 1])) };
    check_eq!(v, 0x01000001);
    let a: [u16; 2] = unsafe { mem::transmute(bb(0xaaaa5555u32)) };
    check_eq!(a, [0x5555, 0xaaaa]);
    let z: u64 = unsafe { mem::zeroed() };
    check_eq!(bb(z), 0);
    let c: u16 = unsafe { mem::transmute_copy(&bb(0x11223344u32)) };
    check_eq!(c, 0x3344);
});

test!(mem_maybe_uninit, {
    let mut x = MaybeUninit::<u64>::uninit();
    x.write(bb(5));
    check_eq!(unsafe { x.assume_init() }, 5);
    let mut arr: [MaybeUninit<u32>; 8] = [const { MaybeUninit::uninit() }; 8];
    for (i, e) in arr.iter_mut().enumerate() {
        e.write(i as u32 * bb(3));
    }
    let arr: [u32; 8] = unsafe { mem::transmute(arr) };
    check_eq!(arr.iter().sum::<u32>(), 84);
    let z = MaybeUninit::<[u8; 32]>::zeroed();
    check_eq!(unsafe { z.assume_init() }[31], 0);
});

static mut DROPS: u32 = 0;
struct Guard(u32);
impl Drop for Guard {
    fn drop(&mut self) {
        unsafe { DROPS += self.0 };
    }
}
fn drops() -> u32 {
    unsafe { ptr::read_volatile(&raw const DROPS) }
}

test!(mem_drop_forget_manually, {
    let d = drops();
    drop(Guard(bb(1)));
    check_eq!(drops(), d + 1);
    mem::forget(Guard(bb(10)));
    check_eq!(drops(), d + 1);
    let mut m = ManuallyDrop::new(Guard(bb(100)));
    check_eq!(m.0, 100);
    check_eq!(drops(), d + 1);
    unsafe { ManuallyDrop::drop(&mut m) };
    check_eq!(drops(), d + 101);
    {
        let _a = Guard(1000);
        let _b = Guard(2000);
        let _ = Guard(bb(4000));
        check_eq!(drops(), d + 4101);
    }
    check_eq!(drops(), d + 7101);
    let arr = [Guard(1), Guard(1), Guard(bb(2))];
    check_eq!(drops(), d + 7101);
    drop(arr);
    check_eq!(drops(), d + 7105);
    let mut slot = MaybeUninit::new(Guard(5));
    unsafe { ptr::drop_in_place(slot.as_mut_ptr()) };
    check_eq!(drops(), d + 7110);
});

test!(ptr_raw, {
    let mut a = bb([1u32, 2, 3, 4, 5, 6]);
    let p = a.as_mut_ptr();
    unsafe {
        check_eq!(*p.add(2), 3);
        *p.add(2) = 30;
        check_eq!(p.add(5).offset_from(p), 5);
        check_eq!(ptr::read(p.add(1)), 2);
        ptr::write(p, 10);
        ptr::swap(p, p.add(5));
        ptr::copy(p, p.add(1), 3);
        ptr::copy_nonoverlapping(p.add(5), p, 1);
        check_eq!(ptr::replace(p.add(4), 50), 5);
    }
    check_eq!(a, [10, 6, 2, 30, 50, 10]);
    unsafe { ptr::write_bytes(p, 0xff, 2) };
    check_eq!(a[1], u32::MAX);
    check!(ptr::null::<u8>().is_null() && !p.is_null());
    check!(ptr::eq(&a[0], p) && !ptr::eq(&a[1], p));
    check_eq!((p as usize) % 4, 0);
    check_eq!(p.wrapping_add(1) as usize - p as usize, 4);
    check_eq!(unsafe { p.cast::<u8>().add(4).cast::<u32>().read() }, u32::MAX);
});

test!(ptr_nonnull_slices, {
    let mut v = bb([1u64, 2, 3, 4]);
    let nn = NonNull::new(v.as_mut_ptr()).unwrap();
    check_eq!(unsafe { *nn.as_ptr().add(3) }, 4);
    check_eq!(unsafe { *nn.add(1).as_ref() }, 2);
    check!(NonNull::new(bb(ptr::null_mut::<u8>())).is_none());
    check_eq!(NonNull::<u64>::dangling().as_ptr() as usize, 8);
    let s = unsafe { core::slice::from_raw_parts(v.as_ptr().add(1), 2) };
    check_eq!(s, &[2, 3]);
    let m = unsafe { core::slice::from_raw_parts_mut(v.as_mut_ptr(), 2) };
    m[1] = 20;
    check_eq!(v[1], 20);
    let fat = ptr::slice_from_raw_parts(v.as_ptr(), 3);
    check_eq!(fat.len(), 3);
    check_eq!(core::slice::from_ref(&v[2]), &[3]);
    let r = v.as_ptr_range();
    check_eq!(unsafe { r.end.offset_from(r.start) }, 4);
});

test!(ptr_volatile_addr_of, {
    let mut m = Mixed { a: 1, b: bb(2), c: 3 };
    let pb = &raw mut m.b;
    unsafe {
        ptr::write_volatile(pb, 20);
        check_eq!(ptr::read_volatile(pb), 20);
    }
    check_eq!(pb as usize - &raw const m as usize, 8);
    check!(m.a == 1 && m.b == 20 && m.c == 3);
});

test!(cell_cell, {
    let c = Cell::new(bb(5));
    c.set(c.get() + 1);
    check_eq!(c.replace(10), 6);
    check_eq!(c.take(), 10);
    check_eq!(c.get(), 0);
    let d = Cell::new(3);
    c.swap(&d);
    check!(c.get() == 3 && d.get() == 0);
    let arr = [Cell::new(1), Cell::new(2)];
    let (a, b) = (&arr[0], &arr[1]);
    a.set(b.get() + a.get());
    check_eq!(arr[0].get(), 3);
    check_eq!(c.into_inner(), 3);
    let mut v = bb([1, 2, 3]);
    let cs = Cell::from_mut(&mut v[..]).as_slice_of_cells();
    cs[0].set(cs[2].get());
    check_eq!(v, [3, 2, 3]);
});

test!(cell_refcell, {
    let r = RefCell::new(bb([1, 2, 3]));
    {
        let a = r.borrow();
        let b = r.borrow();
        check_eq!(a[0] + b[2], 4);
        check!(r.try_borrow_mut().is_err());
    }
    {
        let mut m = r.borrow_mut();
        m[1] = 20;
        check!(r.try_borrow().is_err());
    }
    check_eq!(r.borrow()[1], 20);
    check_eq!(r.replace([0; 3]), [1, 20, 3]);
    *r.borrow_mut() = [7; 3];
    let first = core::cell::Ref::map(r.borrow(), |a| &a[0]);
    check_eq!(*first, 7);
    drop(first);
    check_eq!(r.into_inner(), [7; 3]);
});

test!(cell_once_unsafe, {
    let o = OnceCell::new();
    check!(o.get().is_none());
    check_eq!(*o.get_or_init(|| bb(5)), 5);
    check_eq!(*o.get_or_init(|| 6), 5);
    check_eq!(o.set(7), Err(7));
    let u = UnsafeCell::new(bb(1));
    unsafe { *u.get() += 1 };
    check_eq!(u.into_inner(), 2);
    let l = core::cell::LazyCell::new(|| bb(40) + 2);
    check_eq!(*l, 42);
});

test!(mem_big_locals, {
    let mut a = [0u64; 512];
    for i in 0..a.len() {
        a[i] = i as u64 * bb(2);
    }
    let b = a;
    a[bb(511)] = 0;
    check_eq!(b[511], 1022);
    check_eq!(b.iter().sum::<u64>(), 511 * 512);
    check_eq!(a.iter().sum::<u64>(), 511 * 512 - 1022);
});

#[inline(never)]
fn by_value(a: [u64; 40], i: usize) -> [u64; 40] {
    let mut b = a;
    b[i] += 1;
    b
}

test!(mem_big_by_value, {
    let a = bb([3u64; 40]);
    let b = by_value(a, bb(39));
    let c = by_value(b, bb(0));
    check!(a[39] == 3 && b[39] == 4 && b[0] == 3 && c[0] == 4 && c[39] == 4);
});

test!(pin_and_any, {
    use core::any::{Any, TypeId};
    use core::pin::{Pin, pin};
    let mut v = bb(5);
    let mut p = Pin::new(&mut v);
    *p += 1;
    check_eq!(*p.as_ref(), 6);
    let q = pin!(bb(7u8));
    check_eq!(*q, 7);
    let a: &dyn Any = &bb(5u32);
    check_eq!(a.downcast_ref::<u32>(), Some(&5));
    check!(a.downcast_ref::<i32>().is_none() && a.is::<u32>());
    check!(TypeId::of::<u32>() != TypeId::of::<i32>());
    check_eq!(a.type_id(), TypeId::of::<u32>());
    check!(core::any::type_name::<Option<u8>>().ends_with("Option<u8>"));
});
