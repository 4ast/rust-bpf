// SPDX-License-Identifier: GPL-2.0
//! Packets: three ways to look at the same bytes.
#![no_std]
#![no_main]
use rt::{bb, check, check_eq, test};
use zerocopy::byteorder::network_endian::U16;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

// Ethernet, IPv4 10.0.0.1 -> 10.0.0.2, UDP 8080 -> 53, 4 bytes
const PKT: [u8; 46] = [
    2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x08, 0x00,
    0x45, 0x00, 0x00, 0x20, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x14, 0x97, 10, 0, 0, 1, 10, 0, 0, 2,
    0x1f, 0x90, 0x00, 0x35, 0x00, 0x0c, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
];

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct UdpHdr {
    src: U16,
    dst: U16,
    len: U16,
    csum: U16,
}

test!(zerocopy_headers, {
    let b = bb(PKT);
    let (h, rest) = UdpHdr::ref_from_prefix(&b[34..]).unwrap();
    check_eq!(h.src.get(), 8080);
    check_eq!(h.dst.get(), 53);
    check_eq!(h.len.get(), 12);
    check_eq!(rest, [0xde, 0xad, 0xbe, 0xef]);
    let h2 = UdpHdr { src: U16::new(bb(1)), dst: U16::new(2), len: U16::new(8), csum: U16::new(0xffff) };
    check_eq!(h2.as_bytes(), [0, 1, 0, 2, 0, 8, 0xff, 0xff]);
    check!(UdpHdr::ref_from_bytes(&b[..7]).is_err());
    check_eq!(u32::read_from_bytes(&b[42..46]).unwrap(), u32::from_ne_bytes([0xde, 0xad, 0xbe, 0xef]));
    let mut m = b;
    let (hm, _) = UdpHdr::mut_from_prefix(&mut m[34..]).unwrap();
    hm.dst.set(5353);
    check_eq!(m[36..38], [0x14, 0xe9]);
});

test!(etherparse_slices, {
    use etherparse::{NetSlice, SlicedPacket, TransportSlice};
    let b = bb(PKT);
    let p = SlicedPacket::from_ethernet(&b).unwrap();
    match &p.net {
        Some(NetSlice::Ipv4(ip)) => {
            let h = ip.header();
            check_eq!(h.source(), [10, 0, 0, 1]);
            check_eq!(h.destination(), [10, 0, 0, 2]);
            check_eq!(h.ttl(), 64);
            check_eq!(h.total_len(), 32);
            check_eq!(h.header_checksum(), 0x1497);
            check_eq!(h.to_header().calc_header_checksum(), 0x1497);
        }
        _ => check!(false),
    }
    match &p.transport {
        Some(TransportSlice::Udp(u)) => {
            check_eq!(u.source_port(), 8080);
            check_eq!(u.destination_port(), 53);
            check_eq!(u.payload(), [0xde, 0xad, 0xbe, 0xef]);
        }
        _ => check!(false),
    }
    check!(SlicedPacket::from_ethernet(&b[..30]).is_err());
    check!(SlicedPacket::from_ethernet(&b[..10]).is_err());
});

test!(smoltcp_wire, {
    use smoltcp::wire::{EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Address, Ipv4Packet, UdpPacket};
    let b = bb(PKT);
    let f = EthernetFrame::new_checked(&b[..]).unwrap();
    check_eq!(f.ethertype(), EthernetProtocol::Ipv4);
    let ip = Ipv4Packet::new_checked(f.payload()).unwrap();
    check!(ip.verify_checksum());
    check_eq!(ip.src_addr(), Ipv4Address::new(10, 0, 0, 1));
    check_eq!(ip.next_header(), IpProtocol::Udp);
    check_eq!(ip.hop_limit(), 64);
    let u = UdpPacket::new_checked(ip.payload()).unwrap();
    check_eq!(u.src_port(), 8080);
    check_eq!(u.payload(), [0xde, 0xad, 0xbe, 0xef]);
    let mut m = b;
    let mut ip = Ipv4Packet::new_unchecked(&mut m[14..]);
    ip.set_hop_limit(63);
    check!(!ip.verify_checksum());
    ip.fill_checksum();
    check!(ip.verify_checksum());
    check_eq!(ip.checksum(), 0x1597);
    check!(Ipv4Packet::new_checked(&b[14..30]).is_err());
});
