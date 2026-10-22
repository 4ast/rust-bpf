// SPDX-License-Identifier: GPL-2.0
//! crates: bytes, bumpalo, slotmap, bytemuck, crossbeam-queue, miniz_oxide, lz4_flex, adler2
#![no_std]
#![no_main]
extern crate alloc;
use alloc::vec::Vec;
use rt::{bb, check, check_eq, test};

test!(bytes_buf, {
    use bytes::{Buf, BufMut, Bytes, BytesMut};
    let mut b = BytesMut::with_capacity(bb(16));
    b.put_u8(1);
    b.put_u16(0x0203);
    b.put_u32_le(0x07060504);
    b.put_slice(bb(b"tail"));
    check_eq!(&b[..], &[1, 2, 3, 4, 5, 6, 7, b't', b'a', b'i', b'l']);
    let mut f: Bytes = b.freeze();
    let c = f.clone();
    check_eq!(f.get_u8(), 1);
    check_eq!(f.get_u16(), 0x0203);
    check_eq!(f.get_u32_le(), 0x07060504);
    check_eq!(f.remaining(), 4);
    let t = f.split_to(bb(2));
    check!(&t[..] == b"ta" && &f[..] == b"il");
    check_eq!(c.len(), 11);
    check_eq!(c.slice(7..9), t);
    let s = Bytes::from_static(b"static");
    check_eq!(s.slice(..3), Bytes::from_static(b"sta"));
    let mut m = BytesMut::from(&bb(b"hello world")[..]);
    let w = m.split_off(6);
    check!(&m[..] == b"hello " && &w[..] == b"world");
    m.unsplit(w);
    check_eq!(&m[..], b"hello world");
    let mut ch = (&bb(b"ab")[..]).chain(&b"cd"[..]);
    check_eq!(ch.get_u32(), 0x61626364);
});

test!(bumpalo_arena, {
    use bumpalo::Bump;
    use bumpalo::collections::{String as BString, Vec as BVec};
    let live = rt::live();
    {
        let bump = Bump::new();
        let a = bump.alloc(bb(5u64));
        let b = bump.alloc([bb(1u32); 16]);
        *a += 1;
        b[15] = 9;
        check!(*a == 6 && b.iter().sum::<u32>() == 24);
        let s = bump.alloc_str(bb("hello"));
        check_eq!(s, "hello");
        let sl = bump.alloc_slice_copy(bb(&[1u8, 2, 3]));
        check_eq!(sl, &[1, 2, 3]);
        let mut v = BVec::new_in(&bump);
        for i in 0..bb(200u32) {
            v.push(i);
        }
        check_eq!(v.iter().sum::<u32>(), 19900);
        let mut t = BString::new_in(&bump);
        t.push_str("in the arena");
        check_eq!(t.len(), 12);
        let bx = bumpalo::boxed::Box::new_in(bb(7u8), &bump);
        check_eq!(*bx, 7);
        check!(bump.allocated_bytes() >= 800);
    }
    check_eq!(rt::live(), live);
});

test!(slotmap_keys, {
    use slotmap::{SecondaryMap, SlotMap};
    let mut sm = SlotMap::new();
    let a = sm.insert(bb("a"));
    let b = sm.insert("b");
    let c = sm.insert("c");
    check_eq!(sm[b], "b");
    check_eq!(sm.remove(b), Some("b"));
    check!(!sm.contains_key(b) && sm.get(b).is_none());
    let d = sm.insert("d");
    check!(d != b && sm.get(b).is_none() && sm[d] == "d");
    check_eq!(sm.len(), 3);
    let mut sec = SecondaryMap::new();
    sec.insert(a, 1);
    sec.insert(c, 3);
    check_eq!(sec.get(a).copied().unwrap_or(0) + sec.get(c).copied().unwrap_or(0) + sec.get(d).copied().unwrap_or(0), 4);
    sm.retain(|_, v| *v != "a");
    check_eq!(sm.values().count(), 2);
    check_eq!(sm.remove(b), None);
});

#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable, PartialEq, Debug)]
#[repr(C)]
struct Hdr {
    kind: u16,
    len: u16,
    id: u32,
}

test!(bytemuck_casts, {
    let h = bb(Hdr { kind: 1, len: 2, id: 0x01020304 });
    check_eq!(bytemuck::bytes_of(&h), &[1, 0, 2, 0, 4, 3, 2, 1]);
    let raw = bb([[1u8, 0, 2, 0, 4, 3, 2, 1], [9, 0, 8, 0, 0, 0, 0, 0]]);
    let aligned: [u64; 2] = bytemuck::cast(raw);
    let hs: &[Hdr] = bytemuck::cast_slice(&aligned);
    check!(hs.len() == 2 && hs[0] == h && hs[1].kind == 9);
    check_eq!(bytemuck::cast::<u32, [u8; 4]>(bb(0x04030201)), [1, 2, 3, 4]);
    check_eq!(bytemuck::pod_read_unaligned::<u32>(&raw[0][1..5]), 0x04000200);
    check!(bytemuck::try_from_bytes::<Hdr>(&raw[0][..7]).is_err());
    check!(bytemuck::try_cast_slice::<u8, u32>(&raw[0][..6]).is_err());
    let z: Hdr = bytemuck::Zeroable::zeroed();
    check_eq!(z.id, 0);
});

test!(crossbeam_queues, {
    use crossbeam_queue::{ArrayQueue, SegQueue};
    let q = ArrayQueue::new(bb(3));
    check!(q.push(1).is_ok() && q.push(2).is_ok() && q.push(3).is_ok());
    check_eq!(q.push(4), Err(4));
    check!(q.is_full());
    check_eq!(q.force_push(5), Some(1));
    check_eq!(q.pop(), Some(2));
    check_eq!(q.len(), 2);
    let s = SegQueue::new();
    for i in 0..bb(100u32) {
        s.push(i);
    }
    check_eq!(s.len(), 100);
    let mut sum = 0;
    while let Some(v) = s.pop() {
        sum += v;
    }
    check_eq!(sum, 4950);
    check!(s.is_empty());
});

fn sample(n: usize) -> Vec<u8> {
    let words: [&[u8]; 4] = [b"the quick ", b"brown fox ", b"jumps over ", b"the lazy dog. "];
    let mut v = Vec::new();
    let mut x = bb(1u32);
    while v.len() < n {
        x = x.wrapping_mul(1103515245).wrapping_add(12345);
        v.extend_from_slice(words[(x >> 16) as usize & 3]);
    }
    v.truncate(n);
    v
}

test!(miniz_round_trip, {
    let data = sample(bb(3000));
    let z = miniz_oxide::deflate::compress_to_vec(&data, 6);
    check!(z.len() < data.len() / 3);
    check!(miniz_oxide::inflate::decompress_to_vec(&z).ok().as_deref() == Some(&data[..]));
    let zl = miniz_oxide::deflate::compress_to_vec_zlib(&data, 1);
    check!(miniz_oxide::inflate::decompress_to_vec_zlib(&zl).ok().as_deref() == Some(&data[..]));
    check!(miniz_oxide::inflate::decompress_to_vec_zlib(&zl[..zl.len() / 2]).is_err());
});

test!(miniz_inflate_known, {
    // python: zlib.compress(b"hello hello hello hello", 9)
    let z = bb([0x78u8, 0xda, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40, 0x27, 0x01, 0x68, 0x03, 0x08, 0xb1]);
    check!(miniz_oxide::inflate::decompress_to_vec_zlib(&z).ok().as_deref() == Some(&b"hello hello hello hello"[..]));
});

test!(lz4_round_trip, {
    let data = sample(bb(3000));
    let z = lz4_flex::compress_prepend_size(&data);
    check!(z.len() < data.len() / 2);
    check!(lz4_flex::decompress_size_prepended(&z).ok().as_deref() == Some(&data[..]));
    let b = lz4_flex::block::compress(&data);
    check!(lz4_flex::block::decompress(&b, data.len()).ok().as_deref() == Some(&data[..]));
    check!(lz4_flex::block::decompress(&b[..b.len() - 5], data.len()).is_err());
});

test!(adler32, {
    let mut a = adler2::Adler32::new();
    a.write_slice(bb(b"Wikipedia"));
    check_eq!(a.checksum(), 0x11e60398);
    check_eq!(adler2::adler32_slice(bb(b"")), 1);
});
