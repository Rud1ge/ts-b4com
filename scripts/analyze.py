from pathlib import Path

from rich.console import Console
from rich.table import Table
from scapy.all import IP, UDP, PcapReader

console = Console()
NEXTHOPS = ["Nexthop-1", "Nexthop-2"]


def collect_stats(pcap_file):
    unique_src = set()
    packets = 0

    with PcapReader(str(pcap_file)) as pcap:
        for pkt in pcap:
            ip = pkt.getlayer(IP)
            if ip and ip.dst == "172.16.0.254" and pkt.haslayer(UDP):
                packets += 1
                unique_src.add(ip.src)

    return packets, len(unique_src)


def analyze_pcaps(timestamp, nexthops):
    table = Table(
        title=f"UDP -> 172.16.0.254, разбор на конечных точках ({timestamp})",
        title_justify="left",
        header_style="bold",
    )
    table.add_column("Контейнер", no_wrap=True)
    table.add_column("Файл дампа", overflow="fold")
    table.add_column("UDP пакеты", justify="right")
    table.add_column("Уникальные src", justify="right")
    table.add_column("Доля уникальных src", justify="right")

    rows = []
    total_packets = 0
    total_unique = 0

    for nh in nexthops:
        pcap_file = Path("pcaps") / f"{nh}_{timestamp}.pcap"
        packets, uniq = collect_stats(pcap_file)
        rows.append((nh, pcap_file, packets, uniq))
        total_packets += packets
        total_unique += uniq

    for nh, pcap_file, packets, uniq in rows:
        share = (uniq / total_unique * 100) if total_unique else 0
        table.add_row(nh, str(pcap_file), str(packets), str(uniq), f"{share:.1f}%")

    table.add_section()
    table.add_row("[bold]Итого[/bold]", "", f"[bold]{total_packets}[/bold]", f"[bold]{total_unique}[/bold]", "")
    console.print(table)

    if total_unique:
        expected = 100 / len(nexthops)
        worst = 0.0
        for nh, pcap_file, packets, uniq in rows:
            dev = abs((uniq / total_unique * 100) - expected)
            if dev > worst:
                worst = dev
        console.print(f"Фактическое отклонение: {worst:.1f}%.")
