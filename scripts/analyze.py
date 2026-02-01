from pathlib import Path

from rich.console import Console
from rich.table import Table
from scapy.all import IP, UDP, PcapReader

console = Console()


def collect_unique_sources(pcap_file_path):
    unique_source_ip_set = set()
    udp_packet_count = 0

    with PcapReader(str(pcap_file_path)) as pcap_reader:
        for packet in pcap_reader:
            ip_layer = packet.getlayer(IP)
            if ip_layer is None:
                continue

            if ip_layer.dst != "172.16.0.254":
                continue

            if not packet.haslayer(UDP):
                continue

            udp_packet_count += 1
            unique_source_ip_set.add(ip_layer.src)

    return udp_packet_count, unique_source_ip_set


def analyze_pcaps(timestamp, nexthops):
    rows = []
    total_udp_packets = 0

    all_unique_sources = set()

    for nexthop_name in nexthops:
        pcap_file_path = Path("pcaps") / f"{nexthop_name}_{timestamp}.pcap"
        udp_packets, unique_sources = collect_unique_sources(pcap_file_path)

        rows.append(
            {
                "nexthop_name": nexthop_name,
                "pcap_file_path": pcap_file_path,
                "udp_packets": udp_packets,
                "unique_sources": unique_sources,
            }
        )

        total_udp_packets += udp_packets
        all_unique_sources.update(unique_sources)

    total_unique_sources = len(all_unique_sources)

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

    for row in rows:
        unique_count = len(row["unique_sources"])

        if total_unique_sources == 0:
            share_percent = 0.0
        else:
            share_percent = unique_count / total_unique_sources * 100.0

        table.add_row(
            row["nexthop_name"],
            str(row["pcap_file_path"]),
            str(row["udp_packets"]),
            str(unique_count),
            f"{share_percent:.1f}%",
        )

    table.add_section()
    table.add_row(
        "[bold]Итого[/bold]",
        "",
        f"[bold]{total_udp_packets}[/bold]",
        f"[bold]{total_unique_sources}[/bold]",
        "",
    )
    console.print(table)

    if total_unique_sources == 0:
        return

    expected_share_percent = 100.0 / len(nexthops)
    worst_deviation_percent = 0.0

    for row in rows:
        unique_count = len(row["unique_sources"])
        share_percent = unique_count / total_unique_sources * 100.0

        deviation = share_percent - expected_share_percent
        if deviation < 0:
            deviation = -deviation

        if deviation > worst_deviation_percent:
            worst_deviation_percent = deviation

    console.print(f"Фактическое отклонение: {worst_deviation_percent:.1f}%.")
