// SPDX-License-Identifier: GPL-2.0
//! Small programs: the shapes of loops and data that real code has.
#![no_std]
#![no_main]
extern crate alloc;
use alloc::collections::{BTreeMap, BinaryHeap, VecDeque};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Reverse;
use rt::{bb, check, check_eq, test};

test!(algo_sieve, {
    let n = bb(1000usize);
    let mut comp = vec![false; n + 1];
    let mut primes = Vec::new();
    for i in 2..=n {
        if !comp[i] {
            primes.push(i);
            let mut j = i * i;
            while j <= n {
                comp[j] = true;
                j += i;
            }
        }
    }
    check_eq!(primes.len(), 168);
    check_eq!(primes[167], 997);
    check_eq!(primes.iter().sum::<usize>(), 76127);
});

test!(algo_matrix, {
    const N: usize = 8;
    let mut a = [[0i64; N]; N];
    let mut b = [[0i64; N]; N];
    for i in 0..N {
        for j in 0..N {
            a[i][j] = (i * N + j) as i64 + bb(0);
            b[i][j] = if i == j { 2 } else { (i as i64 - j as i64) % 3 };
        }
    }
    let mut c = [[0i64; N]; N];
    for i in 0..N {
        for j in 0..N {
            for k in 0..N {
                c[i][j] += a[i][k] * b[k][j];
            }
        }
    }
    let trace: i64 = (0..N).map(|i| c[i][i]).sum();
    let total: i64 = c.iter().flatten().sum();
    check_eq!(trace, -84);
    check_eq!(total, 4704);
});

test!(algo_lcs_edit_distance, {
    fn lcs(a: &[u8], b: &[u8]) -> usize {
        let mut dp = vec![vec![0usize; b.len() + 1]; a.len() + 1];
        for i in 1..=a.len() {
            for j in 1..=b.len() {
                dp[i][j] = if a[i - 1] == b[j - 1] { dp[i - 1][j - 1] + 1 } else { dp[i - 1][j].max(dp[i][j - 1]) };
            }
        }
        dp[a.len()][b.len()]
    }
    fn edit(a: &[u8], b: &[u8]) -> usize {
        let mut prev: Vec<usize> = (0..=b.len()).collect();
        for i in 1..=a.len() {
            let mut cur = vec![i; b.len() + 1];
            for j in 1..=b.len() {
                cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + (a[i - 1] != b[j - 1]) as usize);
            }
            prev = cur;
        }
        prev[b.len()]
    }
    check_eq!(lcs(bb(b"AGGTAB"), bb(b"GXTXAYB")), 4);
    check_eq!(lcs(bb(b"the quick brown fox"), bb(b"a quick brown dog")), 14);
    check_eq!(edit(bb(b"kitten"), bb(b"sitting")), 3);
    check_eq!(edit(bb(b""), bb(b"abc")), 3);
    check_eq!(edit(bb(b"intention"), bb(b"execution")), 5);
});

test!(algo_kmp, {
    fn kmp(hay: &[u8], pat: &[u8]) -> Vec<usize> {
        let mut fail = vec![0usize; pat.len()];
        let mut k = 0;
        for i in 1..pat.len() {
            while k > 0 && pat[i] != pat[k] {
                k = fail[k - 1];
            }
            if pat[i] == pat[k] {
                k += 1;
            }
            fail[i] = k;
        }
        let (mut out, mut k) = (Vec::new(), 0);
        for (i, &c) in hay.iter().enumerate() {
            while k > 0 && c != pat[k] {
                k = fail[k - 1];
            }
            if c == pat[k] {
                k += 1;
            }
            if k == pat.len() {
                out.push(i + 1 - k);
                k = fail[k - 1];
            }
        }
        out
    }
    check_eq!(kmp(bb(b"abababcabababab"), bb(b"abab")), [0, 2, 7, 9, 11]);
    check_eq!(kmp(bb(b"aaaaa"), bb(b"aa")), [0, 1, 2, 3]);
    check!(kmp(bb(b"abc"), bb(b"d")).is_empty());
});

test!(algo_nqueens, {
    fn solve(n: usize, row: usize, cols: u32, d1: u32, d2: u32) -> u32 {
        if row == n {
            return 1;
        }
        let mut free = !(cols | d1 | d2) & ((1 << n) - 1);
        let mut count = 0;
        while free != 0 {
            let bit = free & free.wrapping_neg();
            free ^= bit;
            count += solve(n, row + 1, cols | bit, (d1 | bit) << 1, (d2 | bit) >> 1);
        }
        count
    }
    check_eq!(solve(bb(6), 0, 0, 0, 0), 4);
    check_eq!(solve(bb(8), 0, 0, 0, 0), 92);
});

test!(algo_dijkstra_grid, {
    let grid: [&[u8]; 6] = [b"113111", b"191191", b"111191", b"999191", b"111111", b"199991"];
    let (h, w) = (grid.len(), grid[0].len());
    let mut dist = vec![vec![u32::MAX; w]; h];
    let mut q = BinaryHeap::new();
    dist[0][0] = 0;
    q.push(Reverse((bb(0u32), 0usize, 0usize)));
    while let Some(Reverse((d, y, x))) = q.pop() {
        if d > dist[y][x] {
            continue;
        }
        for (dy, dx) in [(0i32, 1i32), (1, 0), (0, -1), (-1, 0)] {
            let (ny, nx) = (y as i32 + dy, x as i32 + dx);
            if ny < 0 || nx < 0 || ny >= h as i32 || nx >= w as i32 {
                continue;
            }
            let (ny, nx) = (ny as usize, nx as usize);
            let nd = d + (grid[ny][nx] - b'0') as u32;
            if nd < dist[ny][nx] {
                dist[ny][nx] = nd;
                q.push(Reverse((nd, ny, nx)));
            }
        }
    }
    check_eq!(dist[5][5], 10);
    check_eq!(dist[5][0], 11);
});

test!(algo_bfs_flood, {
    let map: [&[u8]; 5] = [b"..#....", b".##.##.", b"....#..", b"###.#.#", "......#".as_bytes()];
    let (h, w) = (map.len(), map[0].len());
    let mut seen = vec![vec![false; w]; h];
    let mut q = VecDeque::new();
    q.push_back((bb(0usize), 0usize, 0u32));
    seen[0][0] = true;
    let (mut reached, mut far) = (0, 0);
    while let Some((y, x, d)) = q.pop_front() {
        reached += 1;
        far = far.max(d);
        let mut go = |ny: usize, nx: usize| {
            if map[ny][nx] == b'.' && !seen[ny][nx] {
                seen[ny][nx] = true;
                q.push_back((ny, nx, d + 1));
            }
        };
        if y > 0 {
            go(y - 1, x);
        }
        if y + 1 < h {
            go(y + 1, x);
        }
        if x > 0 {
            go(y, x - 1);
        }
        if x + 1 < w {
            go(y, x + 1);
        }
    }
    check_eq!(reached, 23);
    check_eq!(far, 12);
});

test!(algo_union_find, {
    struct Uf(Vec<usize>, Vec<u32>);
    impl Uf {
        fn find(&mut self, mut x: usize) -> usize {
            while self.0[x] != x {
                self.0[x] = self.0[self.0[x]];
                x = self.0[x];
            }
            x
        }
        fn union(&mut self, a: usize, b: usize) -> bool {
            let (a, b) = (self.find(a), self.find(b));
            if a == b {
                return false;
            }
            let (a, b) = if self.1[a] < self.1[b] { (b, a) } else { (a, b) };
            self.0[b] = a;
            self.1[a] += self.1[b];
            true
        }
    }
    let n = bb(100);
    let mut u = Uf((0..n).collect(), vec![1; n]);
    let mut merges = 0;
    for i in 0..n {
        if i + 7 < n && u.union(i, i + 7) {
            merges += 1;
        }
    }
    check_eq!(merges, 93);
    check!(u.find(0) == u.find(98) && u.find(0) != u.find(1));
    let r = u.find(3);
    check_eq!(u.1[r], 14);
});

test!(algo_bigint_factorial, {
    let mut digits = vec![1u32];
    for n in 2..=bb(50u32) {
        let mut carry = 0u64;
        for d in digits.iter_mut() {
            let v = *d as u64 * n as u64 + carry;
            *d = (v % 1_000_000_000) as u32;
            carry = v / 1_000_000_000;
        }
        if carry > 0 {
            digits.push(carry as u32);
        }
    }
    let mut s = String::new();
    for (i, d) in digits.iter().rev().enumerate() {
        use core::fmt::Write;
        let _ = if i == 0 { write!(s, "{d}") } else { write!(s, "{d:09}") };
    }
    check_eq!(s, "30414093201713378043612608166064768844377641568960512000000000000");
});

test!(algo_word_count, {
    let text = bb("the cat and the dog and the bird saw a cat");
    let mut m: BTreeMap<&str, u32> = BTreeMap::new();
    for w in text.split(' ') {
        *m.entry(w).or_insert(0) += 1;
    }
    let mut v: Vec<(&str, u32)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    check_eq!(&v[..3], &[("the", 3), ("and", 2), ("cat", 2)]);
    check_eq!(v.len(), 7);
});

test!(algo_rpn_calculator, {
    fn eval(s: &str) -> Option<i64> {
        let mut st: Vec<i64> = Vec::new();
        for t in s.split_whitespace() {
            if let Ok(n) = t.parse() {
                st.push(n);
                continue;
            }
            let (b, a) = (st.pop()?, st.pop()?);
            st.push(match t {
                "+" => a + b,
                "-" => a - b,
                "*" => a * b,
                "/" => a.checked_div(b)?,
                _ => return None,
            });
        }
        if st.len() == 1 { st.pop() } else { None }
    }
    check_eq!(eval(bb("3 4 + 2 *")), Some(14));
    check_eq!(eval(bb("5 1 2 + 4 * + 3 -")), Some(14));
    check_eq!(eval(bb("1 0 /")), None);
    check_eq!(eval(bb("1 +")), None);
    check_eq!(eval(bb("1 2")), None);
});

test!(algo_run_length_base64, {
    fn rle(s: &[u8]) -> Vec<(u8, u8)> {
        let mut out: Vec<(u8, u8)> = Vec::new();
        for &c in s {
            match out.last_mut() {
                Some((l, n)) if *l == c && *n < 255 => *n += 1,
                _ => out.push((c, 1)),
            }
        }
        out
    }
    check_eq!(rle(bb(b"aaabccdddd")), [(b'a', 3), (b'b', 1), (b'c', 2), (b'd', 4)]);
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bb(b"hello world").chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= c.len() { T[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    check_eq!(out, "aGVsbG8gd29ybGQ=");
});

test!(algo_lru_cache, {
    struct Lru {
        cap: usize,
        tick: u64,
        map: BTreeMap<u32, (u32, u64)>,
    }
    impl Lru {
        fn get(&mut self, k: u32) -> Option<u32> {
            self.tick += 1;
            let t = self.tick;
            self.map.get_mut(&k).map(|e| {
                e.1 = t;
                e.0
            })
        }
        fn put(&mut self, k: u32, v: u32) {
            self.tick += 1;
            if !self.map.contains_key(&k) && self.map.len() == self.cap {
                let old = *self.map.iter().min_by_key(|(_, e)| e.1).unwrap().0;
                self.map.remove(&old);
            }
            self.map.insert(k, (v, self.tick));
        }
    }
    let mut c = Lru { cap: bb(2), tick: 0, map: BTreeMap::new() };
    c.put(1, 10);
    c.put(2, 20);
    check_eq!(c.get(1), Some(10));
    c.put(3, 30);
    check_eq!(c.get(2), None);
    c.put(4, 40);
    check_eq!(c.get(1), None);
    check_eq!(c.get(3), Some(30));
    check_eq!(c.get(4), Some(40));
});
