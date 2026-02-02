from pathlib import Path

from rich.console import Console
from rich.table import Table
from scapy.all import IP, UDP, PcapReader

console = Console()

DESTINATION_IP = "172.16.0.254"
PCAP_DIR = Path("pcaps")


def pcap_stats(pcap_path):
    unique_src = set()
    udp_packets = 0

    with PcapReader(str(pcap_path)) as pcap:
        for pkt in pcap:
            ip = pkt.getlayer(IP)
            if not ip or ip.dst != DESTINATION_IP or not pkt.haslayer(UDP):
                continue

            udp_packets += 1
            unique_src.add(ip.src)

    return udp_packets, unique_src


def collect_rows(timestamp, nexthops, test_name):
    rows = []
    total_udp = 0
    all_sources = set()

    for hop in nexthops:
        pcap_path = PCAP_DIR / f"{hop}_{test_name}_{timestamp}.pcap"
        udp, sources = pcap_stats(pcap_path)

        rows.append(
            {
                "hop": hop,
                "pcap": pcap_path,
                "udp": udp,
                "sources": sources,
            }
        )

        total_udp += udp
        all_sources.update(sources)

    return rows, total_udp, all_sources


def print_table(title, rows, total_udp, total_unique):
    table = Table(title=title, title_justify="left", header_style="bold")
    table.add_column("Контейнер", no_wrap=True)
    table.add_column("Файл дампа", overflow="fold")
    table.add_column("UDP пакеты", justify="right")
    table.add_column("Уникальные Source IP", justify="right")
    table.add_column("Доля уникальных Source IP", justify="right")

    for row in rows:
        unique_count = len(row["sources"])
        share = 0.0 if total_unique == 0 else unique_count / total_unique * 100.0
        table.add_row(
            row["hop"],
            str(row["pcap"]),
            str(row["udp"]),
            str(unique_count),
            f"{share:.1f}%",
        )

    table.add_section()
    table.add_row(
        "[bold]Итого[/bold]",
        "",
        f"[bold]{total_udp}[/bold]",
        f"[bold]{total_unique}[/bold]",
        "",
    )
    console.print(table)


def analyze_distribution(timestamp, nexthops, max_deviation_percent, test_name="distribution"):
    nexthops = list(nexthops)
    rows, total_udp, all_sources = collect_rows(timestamp, nexthops, test_name)
    total_unique = len(all_sources)

    print_table(f"ECMP распределение по Source IP ({timestamp})", rows, total_udp, total_unique)

    if total_unique == 0:
        console.print("[red][bold]FAIL[/bold]: не найдено ни одного UDP пакета.[/red]")
        return False

    expected = 100.0 / len(nexthops)
    worst = 0.0

    for row in rows:
        share = len(row["sources"]) / total_unique * 100.0
        worst = max(worst, abs(share - expected))

    console.print(f"[cyan]INFO[/cyan]: фактическое отклонение: {worst:.1f}%.")

    if worst <= max_deviation_percent:
        console.print("[green][bold]PASS[/bold]: распределение ECMP по случайным Source IP в пределах допуска.[/green]")
        return True

    console.print("[red][bold]FAIL[/bold]: распределение ECMP по случайным Source IP выходит за пределы допуска.[/red]")
    return False


def analyze_hash_only_by_source(timestamp, nexthops, test_name="hash-only-source"):
    nexthops = list(nexthops)
    rows, total_udp, all_sources = collect_rows(timestamp, nexthops, test_name)
    total_unique = len(all_sources)

    print_table(f"Hash-only-Source-IP: привязка Source IP к nexthop ({timestamp})", rows, total_udp, total_unique)

    if total_udp == 0:
        console.print("[red][bold]FAIL[/bold]: не найдено ни одного UDP пакета для проверки хэша.[/red]")
        return False

    src_to_hops = {}
    for row in rows:
        hop = row["hop"]
        for src in row["sources"]:
            src_to_hops.setdefault(src, set()).add(hop)

    offenders = {src: hops for src, hops in src_to_hops.items() if len(hops) > 1}

    if offenders:
        console.print("[red][bold]FAIL[/bold]: Source IP распределяется по нескольким nexthop.[/red]")
        for src, hops in sorted(offenders.items()):
            console.print(f"[cyan]INFO[/cyan]: {src} -> {', '.join(sorted(hops))}")
        return False

    console.print(
        "[green][bold]PASS[/bold]: распределение ECMP только по Source IP (один Source IP на один nexthop).[/green]")
    return True
