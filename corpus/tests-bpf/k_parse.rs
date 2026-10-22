// SPDX-License-Identifier: GPL-2.0
//! crates: nom, winnow
#![no_std]
#![no_main]
extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use rt::{bb, check, check_eq, test};

mod n {
    use alloc::vec::Vec;
    use nom::branch::alt;
    use nom::bytes::complete::{tag, take, take_while1};
    use nom::character::complete::{alpha1, char, digit1, multispace0};
    use nom::combinator::{map, map_res, opt, recognize};
    use nom::multi::{fold_many0, many0, separated_list0, separated_list1};
    use nom::number::complete::{be_u16, be_u32, le_u32, u8 as byte};
    use nom::sequence::{delimited, pair, preceded, separated_pair, terminated};
    use nom::{IResult, Parser};

    pub fn number(i: &str) -> IResult<&str, i64> {
        map_res(recognize(pair(opt(char('-')), digit1)), |s: &str| s.parse::<i64>()).parse(i)
    }
    pub fn list(i: &str) -> IResult<&str, Vec<i64>> {
        delimited(char('['), separated_list0(delimited(multispace0, char(','), multispace0), number), char(']')).parse(i)
    }
    pub fn key_value(i: &str) -> IResult<&str, (&str, i64)> {
        separated_pair(alpha1, char('='), number).parse(i)
    }
    pub fn config(i: &str) -> IResult<&str, Vec<(&str, i64)>> {
        separated_list1(char(';'), key_value).parse(i)
    }
    pub fn color(i: &str) -> IResult<&str, (u8, u8, u8)> {
        let hex = || map_res(take(2usize), |s: &str| u8::from_str_radix(s, 16));
        preceded(tag("#"), (hex(), hex(), hex())).parse(i)
    }
    pub fn word_or_num(i: &str) -> IResult<&str, bool> {
        alt((map(alpha1, |_| true), map(digit1, |_| false))).parse(i)
    }
    pub fn idents(i: &str) -> IResult<&str, Vec<&str>> {
        many0(terminated(take_while1(|c: char| c.is_alphanumeric() || c == '_'), multispace0)).parse(i)
    }
    fn factor(i: &str) -> IResult<&str, i64> {
        delimited(multispace0, alt((number, delimited(char('('), expr, char(')')))), multispace0).parse(i)
    }
    fn term(i: &str) -> IResult<&str, i64> {
        let (i, first) = factor(i)?;
        fold_many0(pair(alt((char('*'), char('/'))), factor), move || first, |a, (op, v)| if op == '*' { a * v } else { a / v })
            .parse(i)
    }
    pub fn expr(i: &str) -> IResult<&str, i64> {
        let (i, first) = term(i)?;
        fold_many0(pair(alt((char('+'), char('-'))), term), move || first, |a, (op, v)| if op == '+' { a + v } else { a - v })
            .parse(i)
    }
    pub fn header(i: &[u8]) -> IResult<&[u8], (u8, u16, u32, u32)> {
        (byte, be_u16, be_u32, le_u32).parse(i)
    }
}

test!(nom_numbers_lists, {
    check_eq!(n::number(bb("123abc")), Ok(("abc", 123)));
    check_eq!(n::number(bb("-7")), Ok(("", -7)));
    check!(n::number(bb("x")).is_err());
    check!(n::number(bb("99999999999999999999")).is_err());
    check_eq!(n::list(bb("[1, -2 ,3]")), Ok(("", alloc::vec![1, -2, 3])));
    check_eq!(n::list(bb("[]rest")), Ok(("rest", Vec::new())));
    check!(n::list(bb("[1,")).is_err());
});

test!(nom_config_color, {
    check_eq!(n::key_value(bb("a=1")), Ok(("", ("a", 1))));
    check_eq!(n::config(bb("a=1;bc=-2;d=30 tail")), Ok((" tail", alloc::vec![("a", 1), ("bc", -2), ("d", 30)])));
    check!(n::config(bb("=1")).is_err());
    check_eq!(n::color(bb("#ff8000")), Ok(("", (255, 128, 0))));
    check!(n::color(bb("#ff80")).is_err());
    check!(n::color(bb("#gg0000")).is_err());
    check_eq!(n::word_or_num(bb("abc1")), Ok(("1", true)));
    check_eq!(n::word_or_num(bb("1abc")), Ok(("abc", false)));
    check_eq!(n::idents(bb("a b_1  c2 !")).map(|r| r.1.len()), Ok(3));
});

test!(nom_expression, {
    check_eq!(n::expr(bb("1 + 2 * 3")), Ok(("", 7)));
    check_eq!(n::expr(bb("(1 + 2) * 3")), Ok(("", 9)));
    check_eq!(n::expr(bb("2 * (3 + 4) - 10 / 5")), Ok(("", 12)));
    check_eq!(n::expr(bb("((((7))))")), Ok(("", 7)));
    check!(n::expr(bb("(1 + ")).is_err());
});

test!(nom_binary, {
    let d = bb([7u8, 0x12, 0x34, 0xde, 0xad, 0xbe, 0xef, 1, 0, 0, 0, 99]);
    check_eq!(n::header(&d), Ok((&[99u8][..], (7, 0x1234, 0xdeadbeef, 1))));
    check!(n::header(&d[..5]).is_err());
});

mod w {
    use alloc::vec::Vec;
    use winnow::ascii::{alpha1, dec_int, digit1, multispace0};
    use winnow::combinator::{alt, delimited, opt, preceded, repeat, separated, separated_pair};
    use winnow::prelude::*;
    use winnow::token::{take, take_while};

    pub fn number(i: &mut &str) -> ModalResult<i64> {
        dec_int.parse_next(i)
    }
    pub fn list(i: &mut &str) -> ModalResult<Vec<i64>> {
        delimited('[', separated(0.., number, (multispace0, ',', multispace0)), ']').parse_next(i)
    }
    pub fn key_value<'a>(i: &mut &'a str) -> ModalResult<(&'a str, i64)> {
        separated_pair(alpha1, '=', number).parse_next(i)
    }
    pub fn color(i: &mut &str) -> ModalResult<(u8, u8, u8)> {
        let hex = || take(2usize).try_map(|s: &str| u8::from_str_radix(s, 16));
        preceded('#', (hex(), hex(), hex())).parse_next(i)
    }
    pub fn version(i: &mut &str) -> ModalResult<(u32, u32, Option<u32>)> {
        let n = || digit1.parse_to::<u32>();
        (n(), preceded('.', n()), opt(preceded('.', n()))).parse_next(i)
    }
    pub fn kinds(i: &mut &str) -> ModalResult<Vec<u8>> {
        repeat(0.., alt((alpha1.value(1u8), digit1.value(2u8), take_while(1.., ' ').value(0u8)))).parse_next(i)
    }
}

test!(winnow_basic, {
    use winnow::Parser;
    let mut i = bb("-42rest");
    check_eq!(w::number(&mut i).ok(), Some(-42));
    check_eq!(i, "rest");
    check_eq!(w::list.parse(bb("[1, 2 ,-3]")).ok(), Some(alloc::vec![1, 2, -3]));
    check_eq!(w::list.parse(bb("[]")).ok(), Some(Vec::new()));
    check!(w::list.parse(bb("[1,]")).is_err());
    check!(w::list.parse(bb("[1] trailing")).is_err());
    check_eq!(w::key_value.parse(bb("abc=5")).ok(), Some(("abc", 5)));
});

test!(winnow_more, {
    use winnow::Parser;
    check_eq!(w::color.parse(bb("#0a141e")).ok(), Some((10, 20, 30)));
    check!(w::color.parse(bb("#0a14zz")).is_err());
    check_eq!(w::version.parse(bb("1.22")).ok(), Some((1, 22, None)));
    check_eq!(w::version.parse(bb("1.22.333")).ok(), Some((1, 22, Some(333))));
    check!(w::version.parse(bb("1.")).is_err());
    check_eq!(w::kinds.parse(bb("ab 12 c")).ok(), Some(alloc::vec![1, 0, 2, 0, 1]));
    let e = w::list.parse(bb("[1;2]")).unwrap_err();
    check_eq!(e.offset(), 2);
    let _ = String::new();
});
