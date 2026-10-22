// SPDX-License-Identifier: GPL-2.0
//! Code that procedural macros write: a lexer, trait implementations.
#![no_std]
#![no_main]
extern crate alloc;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use logos::Logos;
use rt::{bb, check, check_eq, test};

#[derive(Logos, Debug, PartialEq, Clone, Copy)]
#[logos(skip r"[ \t\n]+")]
enum Tok {
    #[token("+")]
    Plus,
    #[token("*")]
    Star,
    #[token("(")]
    Open,
    #[token(")")]
    Close,
    #[token("let")]
    Let,
    #[regex("[0-9]+", |l| l.slice().parse::<u32>().ok())]
    Num(u32),
    #[regex("[a-z_][a-z0-9_]*")]
    Ident,
}

test!(logos_lexer, {
    let t: Vec<_> = Tok::lexer(bb("let lettuce (12 + x_1) * 345")).collect();
    check_eq!(
        t,
        [Ok(Tok::Let), Ok(Tok::Ident), Ok(Tok::Open), Ok(Tok::Num(12)), Ok(Tok::Plus), Ok(Tok::Ident), Ok(Tok::Close), Ok(Tok::Star), Ok(Tok::Num(345))]
    );
    let mut l = Tok::lexer(bb("ab ? 7"));
    check_eq!(l.next(), Some(Ok(Tok::Ident)));
    check_eq!(l.slice(), "ab");
    check_eq!(l.span(), 0..2);
    check_eq!(l.next(), Some(Err(())));
    check_eq!(l.next(), Some(Ok(Tok::Num(7))));
    check_eq!(l.next(), None);
});

#[derive(derive_more::Display, derive_more::From, derive_more::Add, derive_more::Into, Clone, Copy, PartialEq, Debug)]
#[display("{_0}ms")]
struct Ms(u64);

#[derive(derive_more::Display, derive_more::From, Debug, PartialEq)]
enum E {
    #[display("io {_0}")]
    Io(i32),
    #[display("bad {name}")]
    Bad { name: &'static str },
}

#[derive(derive_more::Deref)]
struct W(Vec<u32>);

test!(derive_more_traits, {
    let a: Ms = bb(5u64).into();
    check_eq!(a + Ms(7), Ms(12));
    check_eq!(format!("{}", a + Ms(7)), "12ms");
    check_eq!(u64::from(a), 5);
    check_eq!(E::from(bb(-3)), E::Io(-3));
    check_eq!(format!("{} / {}", E::from(-3), E::from("x")), "io -3 / bad x");
    let w = W(vec![bb(1), 2, 3]);
    check_eq!(w.len(), 3);
    check!(w.contains(&2));
});
