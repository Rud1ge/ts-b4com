from scapy.all import IP, UDP, Raw, RandIP, send

SPORT = 12345
DPORT = 54321
PACKETS = 1024


def generate_and_send():
    packets = []
    payload = Raw(load=("ECMP Hash Testing for b4com" * 64).encode())

    for packet in range(PACKETS):
        pkt = IP(dst="172.16.0.254", src=RandIP()) / UDP(sport=SPORT, dport=DPORT) / payload
        packets.append(pkt)

    send(packets, inter=0.01, iface="eth0", verbose=False)


if __name__ == "__main__":
    generate_and_send()
