// SPDX-License-Identifier: GPL-2.0
//! Dates, numbers from and to text, small matrices, hashes with known answers.
#![no_std]
#![no_main]
extern crate alloc;
use alloc::format;
use rt::{bb, check, check_eq, test};

test!(chrono_dates, {
    use chrono::{Datelike, NaiveDate, TimeDelta, Timelike, Weekday};
    let d = NaiveDate::from_ymd_opt(bb(2026), 10, 22).unwrap();
    check_eq!(d.weekday(), Weekday::Thu);
    check_eq!(d.ordinal(), 295);
    check_eq!(d.iso_week().week(), 43);
    let e = d + TimeDelta::days(bb(100));
    check_eq!((e.year(), e.month(), e.day()), (2027, 1, 30));
    check_eq!((e - d).num_days(), 100);
    check_eq!((d - NaiveDate::from_ymd_opt(2000, 3, 1).unwrap()).num_days(), 9731);
    check!(NaiveDate::from_ymd_opt(bb(2025), 2, 29).is_none());
    check!(NaiveDate::from_ymd_opt(bb(2024), 2, 29).is_some());
    let t = d.and_hms_opt(8, 30, 15).unwrap();
    check_eq!(t.and_utc().timestamp(), 1792657815);
    check_eq!(t.minute(), 30);
    check_eq!(format!("{}", t), "2026-10-22 08:30:15");
    check_eq!(NaiveDate::parse_from_str(bb("2024-02-29"), "%Y-%m-%d"), NaiveDate::from_ymd_opt(2024, 2, 29).ok_or(()).map_err(|_| unreachable!()));
    check!(NaiveDate::parse_from_str(bb("2023-02-29"), "%Y-%m-%d").is_err());
});

test!(lexical_numbers, {
    check_eq!(lexical_core::parse::<u64>(bb(b"18446744073709551615")), Ok(u64::MAX));
    check!(lexical_core::parse::<u8>(bb(b"256")).is_err());
    check_eq!(lexical_core::parse::<i32>(bb(b"-12345")), Ok(-12345));
    check_eq!(lexical_core::parse::<f64>(bb(b"3.14159e2")), Ok(314.159));
    check_eq!(lexical_core::parse::<f64>(bb(b"0.1")), Ok(0.1));
    check_eq!(lexical_core::parse_partial::<u32>(bb(b"42abc")), Ok((42, 2)));
    let mut buf = [0u8; lexical_core::BUFFER_SIZE];
    check_eq!(lexical_core::write(bb(1234567u32), &mut buf), b"1234567");
    check_eq!(lexical_core::write(bb(-98765i64), &mut buf), b"-98765");
    check_eq!(lexical_core::write(bb(-0.5f64), &mut buf), b"-0.5");
    check_eq!(lexical_core::write(bb(1e21f64), &mut buf), b"1.0e21");
});

test!(nalgebra_small, {
    use nalgebra::{Matrix2, Matrix3, Vector3};
    let m = Matrix3::new(bb(2.0f64), 0., 1., 1., 3., 2., 1., 1., 4.);
    check_eq!(m.determinant(), 18.0);
    let v = Vector3::new(bb(1.0), 2.0, 3.0);
    check_eq!(m * v, Vector3::new(5.0, 13.0, 15.0));
    let inv = m.try_inverse().unwrap();
    check!((m * inv - Matrix3::identity()).abs().max() < 1e-12);
    check_eq!(v.dot(&v), 14.0);
    check_eq!(v.cross(&Vector3::new(0., 1., 0.)), Vector3::new(-3., 0., 1.));
    check_eq!(Vector3::new(bb(3.0f64), 4.0, 0.0).norm(), 5.0);
    let a = Matrix2::new(bb(1i64), 2, 3, 4);
    check_eq!(a * Matrix2::new(5, 6, 7, 8), Matrix2::new(19, 22, 43, 50));
    check_eq!(a.transpose(), Matrix2::new(1, 3, 2, 4));
    check_eq!(a.trace(), 5);
});

test!(xxhash_known_answers, {
    use xxhash_rust::{xxh3::xxh3_64, xxh32::xxh32, xxh64::xxh64};
    check_eq!(xxh32(bb(b""), 0), 0x02cc5d05);
    check_eq!(xxh64(bb(b""), 0), 0xef46db3751d8e999);
    check_eq!(xxh3_64(bb(b"")), 0x2d06800538d394c2);
    check_eq!(xxh32(bb(b"abc"), 0), 0x32d153ff);
    check_eq!(xxh64(bb(b"abc"), 0), 0x44bc2cf5ad770999);
    check_eq!(xxh3_64(bb(b"abc")), 0x78af5f94892f3950);
    let long = bb([0x5au8; 1000]);
    check!(xxh64(&long, 0) != xxh64(&long, 1));
    check_eq!(xxh3_64(&long), xxh3_64(&bb([0x5au8; 1000])));
});
