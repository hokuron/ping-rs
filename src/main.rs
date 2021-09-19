use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::{
    icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes},
    Packet,
};
use pnet::transport::TransportProtocol::{Ipv4, Ipv6};
use pnet::transport::TransportSender;
use pnet::transport::{icmp_packet_iter, transport_channel};
use pnet::transport::{TransportChannelType, TransportReceiver};
use std::convert::TryInto;
use std::io;
use std::net::IpAddr;
use std::process;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;

fn main() {
    let protocol = TransportChannelType::Layer4(Ipv4(IpNextHeaderProtocols::Icmp));
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            dbg!(e);
            return;
        }
    };

    if send_ping(&mut tx, "google.com", 1).is_ok() {
        recv_ping(&mut rx);
    };
}

fn send_ping(tx: &mut TransportSender, name: &str, sequence: u16) -> io::Result<usize> {
    let mut resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    let mut response = resolver.lookup_ip(name).unwrap();
    let address = match response.iter().next() {
        Some(addr) => addr,
        None => return process::exit(-100),
    };
    let sendtime = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut sbuf = vec![0u8; 16];
    let mut echo_packet = echo_request::MutableEchoRequestPacket::new(&mut sbuf).unwrap();
    echo_packet.set_icmp_type(IcmpTypes::EchoRequest);
    echo_packet.set_identifier(process::id().try_into().unwrap_or(256));
    echo_packet.set_sequence_number(sequence);
    echo_packet.set_payload(&sendtime.to_be_bytes());
    echo_packet.set_checksum(pnet::util::checksum(echo_packet.packet(), 1));

    dbg!(&echo_packet);
    dbg!(&echo_packet.packet());

    tx.send_to(echo_packet, address)
}

fn recv_ping(rx: &mut TransportReceiver) {
    fn calc_rtt(reply_packet: &echo_reply::EchoReplyPacket) -> Option<SystemTime> {
        if reply_packet.get_icmp_type() != IcmpTypes::EchoReply {
            return None;
        }

        let payload = reply_packet.payload();
        if payload.len() != 8 {
            return None;
        }

        let secs = u64::from_be_bytes(payload.try_into().unwrap());
        let senttime = Duration::from_secs(secs);
        Some(SystemTime::now() - senttime)
    }

    let mut rx = icmp_packet_iter(rx);
    loop {
        match rx.next() {
            Ok((packet, _)) => match echo_reply::EchoReplyPacket::new(&packet.packet()) {
                Some(echo_reply) => match calc_rtt(&echo_reply) {
                    Some(rtt) => {
                        dbg!(packet.packet());
                        dbg!(rtt);
                        dbg!(echo_reply);
                    }
                    None => {}
                },
                None => {}
            },
            Err(e) => {
                dbg!(e);
            }
        }
    }
}
