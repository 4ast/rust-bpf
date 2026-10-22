// SPDX-License-Identifier: GPL-2.0
//! Floats. BPF has none: everything is a call into compiler_builtins.
#![no_std]
#![no_main]
use rt::{bb, check, check_eq, test};

test!(float_f64_arith, {
    check_eq!(bb(1.5f64) + bb(2.25), 3.75);
    check_eq!(bb(1.5f64) - bb(2.25), -0.75);
    check_eq!(bb(1.5f64) * bb(2.0), 3.0);
    check_eq!(bb(7.0f64) / bb(2.0), 3.5);
    check_eq!(-bb(1.5f64), -1.5);
    check_eq!(bb(0.1f64) + bb(0.2), 0.30000000000000004);
});

test!(float_f32_arith, {
    check_eq!(bb(1.5f32) + bb(2.25), 3.75);
    check_eq!(bb(1.5f32) * bb(-2.0), -3.0);
    check_eq!(bb(1.0f32) / bb(4.0), 0.25);
    check_eq!(bb(16777216.0f32) + bb(1.0), 16777216.0);
});

test!(float_cmp, {
    check!(bb(1.0f64) < bb(2.0) && bb(2.0f64) >= bb(2.0) && bb(-1.0f64) < bb(0.0));
    check!(bb(0.0f64) == bb(-0.0));
    let nan = bb(0.0f64) / bb(0.0);
    check!(nan != nan && !(nan < 1.0) && !(nan > 1.0) && nan.is_nan());
    check_eq!(bb(1.0f64).partial_cmp(&nan), None);
    check_eq!(bb(1.0f64).total_cmp(&bb(2.0)), core::cmp::Ordering::Less);
    check_eq!(bb(3.0f64).max(bb(5.0)).min(bb(4.0)), 4.0);
    check_eq!(bb(7.5f32).clamp(0.0, 1.0), 1.0);
});

test!(float_convert, {
    check_eq!(bb(3.99f64) as i32, 3);
    check_eq!(bb(-3.99f64) as i64, -3);
    check_eq!(bb(300.0f64) as u8, 255);
    check_eq!(bb(-1.0f64) as u32, 0);
    check_eq!(bb(f64::NAN) as i32, 0);
    check_eq!(bb(1e30f64) as i64, i64::MAX);
    check_eq!(bb(7i32) as f64, 7.0);
    check_eq!(bb(u64::MAX) as f64, 18446744073709551616.0);
    check_eq!(bb(-5i64) as f32, -5.0);
    check_eq!(bb(1.5f32) as f64, 1.5);
    check_eq!(bb(0.1f64) as f32, 0.1f32);
    check_eq!(bb(1u128 << 100) as f64, 1267650600228229401496703205376.0);
    check_eq!(bb(1e20f64) as u128, 100000000000000000000);
});

test!(float_bits, {
    check_eq!(bb(1.0f64).to_bits(), 0x3ff0000000000000);
    check_eq!(f64::from_bits(bb(0x4000000000000000)), 2.0);
    check_eq!(bb(1.0f32).to_bits(), 0x3f800000);
    check_eq!(bb(-2.5f64).abs(), 2.5);
    check_eq!(bb(2.5f64).copysign(bb(-1.0)), -2.5);
    check!(bb(-0.0f64).is_sign_negative() && bb(f64::INFINITY).is_infinite() && bb(1.0f64).is_finite());
    check_eq!(bb(1.0f64).signum(), 1.0);
    check!(bb(1e-310f64).is_subnormal());
    check_eq!(bb(2.5f64).to_le_bytes()[7], 0x40);
});

test!(float_sum_loop, {
    let v = bb([0.5f64, 1.5, 2.5, 3.5]);
    check_eq!(v.iter().sum::<f64>(), 8.0);
    check_eq!(v.iter().product::<f64>(), 6.5625);
    check_eq!(v.iter().cloned().fold(f64::MIN, f64::max), 3.5);
    let mut x = bb(2.0f64);
    for _ in 0..6 {
        x = 0.5 * (x + 2.0 / x);
    }
    check!((x * x - 2.0).abs() < 1e-12);
});

struct Buf {
    b: [u8; 64],
    n: usize,
}
impl core::fmt::Write for Buf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let end = self.n + s.len();
        if end > self.b.len() {
            return Err(core::fmt::Error);
        }
        self.b[self.n..end].copy_from_slice(s.as_bytes());
        self.n = end;
        Ok(())
    }
}
macro_rules! f {
    ($want:expr, $($arg:tt)*) => {{
        use core::fmt::Write;
        let mut b = Buf { b: [0; 64], n: 0 };
        check!(write!(b, $($arg)*).is_ok());
        check!(&b.b[..b.n] == $want.as_bytes());
    }};
}

test!(float_fmt_display, {
    f!("1.5", "{}", bb(1.5f64));
    f!("-0.25", "{}", bb(-0.25f64));
    f!("0.1", "{}", bb(0.1f64));
    f!("0.1", "{}", bb(0.1f32));
    f!("0.30000000000000004", "{}", bb(0.1f64) + bb(0.2));
    f!("3", "{}", bb(3.0f64));
    f!("3.0", "{:?}", bb(3.0f64));
    f!("1000000000000000000000", "{}", bb(1e21f64));
    f!("0.0000001", "{}", bb(1e-7f64));
    f!("1e21", "{:?}", bb(1e21f64));
    f!("NaN inf -inf", "{} {} {}", bb(f64::NAN), bb(f64::INFINITY), bb(f64::NEG_INFINITY));
    f!("179769313486231570000", "{:.21}", "179769313486231570000");
});

test!(float_fmt_precision, {
    f!("3.14", "{:.2}", bb(3.14159f64));
    f!("3", "{:.0}", bb(3.14159f64));
    f!("2.50", "{:.2}", bb(2.5f64));
    f!("   1.500", "{:8.3}", bb(1.5f64));
    f!("0001.500", "{:08.3}", bb(1.5f64));
    f!("+1.5", "{:+}", bb(1.5f64));
    f!("1.2345e3", "{:e}", bb(1234.5f64));
    f!("1.23E3", "{:.2E}", bb(1234.5f64));
    f!("1.00", "{:.2}", bb(0.999f64));
    f!("0.3333333", "{:.7}", bb(1.0f32) / bb(3.0));
});

test!(float_parse, {
    check_eq!(bb("1.5").parse::<f64>(), Ok(1.5));
    check_eq!(bb("-0.25").parse::<f64>(), Ok(-0.25));
    check_eq!(bb("1e3").parse::<f64>(), Ok(1000.0));
    check_eq!(bb("2.5E-3").parse::<f64>(), Ok(0.0025));
    check_eq!(bb("0.1").parse::<f64>(), Ok(0.1));
    check_eq!(bb("0.1").parse::<f32>(), Ok(0.1f32));
    check_eq!(bb("3.4028235e38").parse::<f32>(), Ok(f32::MAX));
    check_eq!(bb("1.7976931348623157e308").parse::<f64>(), Ok(f64::MAX));
    check_eq!(bb("inf").parse::<f64>(), Ok(f64::INFINITY));
    check!(bb("nan").parse::<f64>().unwrap().is_nan());
    check_eq!(bb("1e400").parse::<f64>(), Ok(f64::INFINITY));
    check_eq!(bb("123456789012345678901234567890").parse::<f64>(), Ok(1.2345678901234568e29));
    check!(bb("abc").parse::<f64>().is_err());
    check!(bb("1.5x").parse::<f64>().is_err());
    check!(bb("").parse::<f64>().is_err());
});

test!(float_libm, {
    unsafe extern "C" {
        fn sqrt(x: f64) -> f64;
        fn floor(x: f64) -> f64;
        fn pow(x: f64, y: f64) -> f64;
        fn sin(x: f64) -> f64;
        fn exp(x: f64) -> f64;
        fn log(x: f64) -> f64;
    }
    unsafe {
        check_eq!(sqrt(bb(2.25)), 1.5);
        check_eq!(floor(bb(-2.5)), -3.0);
        check_eq!(pow(bb(2.0), bb(10.0)), 1024.0);
        check!((sin(bb(1.0)) - 0.8414709848078965).abs() < 1e-15);
        check!((exp(bb(1.0)) - core::f64::consts::E).abs() < 1e-15);
        check!((log(bb(10.0)) - core::f64::consts::LN_10).abs() < 1e-15);
    }
});
