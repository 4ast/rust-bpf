// SPDX-License-Identifier: GPL-2.0
//! crates: serde (derive), postcard
#![no_std]
#![no_main]
extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use postcard::{from_bytes, take_from_bytes, to_allocvec, to_slice};
use rt::{bb, check, check_eq, test};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct Point {
    x: i32,
    y: i32,
}
#[derive(Serialize, Deserialize, Debug, PartialEq)]
enum Shape {
    Unit,
    Circle(u32),
    Rect { w: u16, h: u16 },
    Poly(Vec<Point>),
}
#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Doc {
    id: u64,
    name: String,
    tags: Vec<String>,
    shape: Shape,
    opt: Option<i8>,
    pair: (bool, char),
    arr: [u8; 3],
    map: BTreeMap<u8, String>,
}
#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Borrowed<'a> {
    s: &'a str,
    b: &'a [u8],
}

test!(postcard_scalars, {
    check_eq!(to_allocvec(&bb(5u8)).unwrap(), [5]);
    check_eq!(to_allocvec(&bb(300u32)).unwrap(), [0xac, 0x02]);
    check_eq!(to_allocvec(&bb(-1i32)).unwrap(), [1]);
    check_eq!(to_allocvec(&bb(true)).unwrap(), [1]);
    check_eq!(to_allocvec(bb("hi")).unwrap(), [2, b'h', b'i']);
    check_eq!(to_allocvec(&bb(Some(7u8))).unwrap(), [1, 7]);
    check_eq!(to_allocvec(&bb(None::<u8>)).unwrap(), [0]);
    check_eq!(from_bytes::<u32>(bb(&[0xac, 0x02])), Ok(300));
    check_eq!(from_bytes::<i32>(bb(&[1])), Ok(-1));
    check_eq!(from_bytes::<u64>(&to_allocvec(&bb(u64::MAX)).unwrap()), Ok(u64::MAX));
    check_eq!(from_bytes::<i128>(&to_allocvec(&bb(i128::MIN)).unwrap()), Ok(i128::MIN));
    check!(from_bytes::<u32>(bb(&[])).is_err());
    check!(from_bytes::<bool>(bb(&[2])).is_err());
    check!(from_bytes::<u8>(bb(&[0x80])).is_ok());
});

test!(postcard_struct_enum, {
    let p = Point { x: bb(-3), y: 1000 };
    let b = to_allocvec(&p).unwrap();
    check_eq!(b, [5, 0xd0, 0x0f]);
    check_eq!(from_bytes::<Point>(&b), Ok(p));
    for s in [Shape::Unit, Shape::Circle(bb(70000)), Shape::Rect { w: 1, h: 2 }, Shape::Poly(vec![Point { x: 1, y: 2 }; 3])] {
        let b = to_allocvec(&s).unwrap();
        check_eq!(from_bytes::<Shape>(&b), Ok(s));
    }
    check_eq!(to_allocvec(&Shape::Rect { w: bb(1), h: 2 }).unwrap(), [2, 1, 2]);
    check!(from_bytes::<Shape>(bb(&[9])).is_err());
});

test!(postcard_document, {
    let mut map = BTreeMap::new();
    map.insert(bb(1), String::from("one"));
    map.insert(2, String::from("two"));
    let d = Doc {
        id: bb(1 << 40),
        name: String::from("doc"),
        tags: vec![String::from("a"), String::from("bc")],
        shape: Shape::Poly(vec![Point { x: 0, y: -1 }]),
        opt: Some(-5),
        pair: (true, 'é'),
        arr: [1, 2, 3],
        map,
    };
    let b = to_allocvec(&d).unwrap();
    check_eq!(from_bytes::<Doc>(&b), Ok(d));
    check!(from_bytes::<Doc>(&b[..b.len() - 1]).is_err());
});

test!(postcard_slice_borrowed, {
    let n = rt::allocs();
    let mut buf = [0u8; 32];
    let v = Borrowed { s: bb("text"), b: &[1, 2, 3] };
    let used = to_slice(&v, &mut buf).unwrap();
    check_eq!(used.len(), 9);
    let back: Borrowed = from_bytes(used).unwrap();
    check_eq!(back, v);
    check_eq!(rt::allocs(), n);
    let mut small = [0u8; 4];
    check!(to_slice(&v, &mut small).is_err());
    let two = bb([1u8, 2, 3]);
    let (a, rest): (u8, &[u8]) = take_from_bytes(&two).unwrap();
    check!(a == 1 && rest == [2, 3]);
});

test!(postcard_cobs, {
    let p = Point { x: bb(0), y: 0 };
    let mut b = postcard::to_allocvec_cobs(&p).unwrap();
    check!(b[..b.len() - 1].iter().all(|x| *x != 0) && b[b.len() - 1] == 0);
    check_eq!(postcard::from_bytes_cobs::<Point>(&mut b), Ok(p));
});

test!(postcard_floats, {
    let b = to_allocvec(&bb(1.5f32)).unwrap();
    check_eq!(b, 1.5f32.to_le_bytes());
    check_eq!(from_bytes::<f64>(&to_allocvec(&bb(-2.25f64)).unwrap()), Ok(-2.25));
});

#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
struct Attrs {
    #[serde(rename = "n")]
    name: u8,
    #[serde(skip)]
    cache: u32,
    #[serde(with = "twice")]
    doubled: u16,
}
mod twice {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &u16, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u16(v * 2)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u16, D::Error> {
        Ok(u16::deserialize(d)? / 2)
    }
}

test!(serde_attributes, {
    let a = Attrs { name: bb(1), cache: 99, doubled: 5 };
    let b = to_allocvec(&a).unwrap();
    check_eq!(b, [1, 10]);
    check_eq!(from_bytes::<Attrs>(&b), Ok(Attrs { name: 1, cache: 0, doubled: 5 }));
});
