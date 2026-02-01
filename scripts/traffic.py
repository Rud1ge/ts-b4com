from scapy.all import IP, UDP, Raw, RandIP, send
from scapy.volatile import RandShort

DEST = "172.16.0.254"
IFACE = "eth0"
INTER = 0.01

PACKETS = 1024
SPORT, DPORT = 12345, 54321

OCTET = 100
FIXED_SOURCES = 16
PORT_VARIANTS = 64

PAYLOAD = Raw(load=("ECMP Hash Testing for b4com" * 64).encode())


def random_packets(packets=PACKETS):
    for i in range(packets):
        yield IP(dst=DEST, src=RandIP()) / UDP(sport=SPORT, dport=DPORT) / PAYLOAD


def fixed_packets(sources=FIXED_SOURCES, variants=PORT_VARIANTS, start=OCTET):
    for i in range(sources):
        src = f"198.51.100.{start + i}"
        for j in range(variants):
            yield IP(dst=DEST, src=src) / UDP(sport=RandShort(), dport=RandShort()) / PAYLOAD


def send_random_sources():
    send(list(random_packets()), inter=INTER, iface=IFACE, verbose=False)


def send_fixed_sources(variants=PORT_VARIANTS):
    send(list(fixed_packets(variants=variants)), inter=INTER, iface=IFACE, verbose=False)
