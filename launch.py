import asyncio
import subprocess
from datetime import datetime

from rich.console import Console

from scripts.analyze import analyze_pcaps

console = Console()

NEXTHOPS = ["Nexthop-1", "Nexthop-2"]


async def run_command(*args):
    result = subprocess.run(args, check=True, capture_output=True)
    return result


async def generate_traffic():
    console.print("[bold]Этап 3. Генерация трафика в TG-контейнере.[/bold]")
    await run_command("docker", "exec", "Traffic-Generator", "python", "/app/scripts/traffic.py")
    console.print("[green]Traffic-Generator: генерация трафика завершена.[/green]")


async def start_capture():
    console.print("[bold]Этап 2. Запуск захвата UDP трафика на NEXTHOP-контейнерах.[/bold]")

    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    tasks = []

    for nexthop in NEXTHOPS:
        cmd = f'tcpdump -i eth0 -nn -U -w /pcaps/{nexthop}_{ts}.pcap "udp and dst host 172.16.0.254" >/tmp/tcpdump_{nexthop}.log 2>&1 & echo $! > /tmp/tcpdump_{nexthop}.pid'
        console.print(f"{nexthop}: захват запущен -> /pcaps/{nexthop}_{ts}.pcap")
        tasks.append(run_command("docker", "exec", nexthop, "sh", "-lc", cmd))

    await asyncio.gather(*tasks)
    return ts


async def stop_capture():
    console.print("[bold]Этап 4. Остановка захвата трафика.[/bold]")

    tasks = []
    for nexthop in NEXTHOPS:
        cmd = f"kill -2 $(cat /tmp/tcpdump_{nexthop}.pid)"
        tasks.append(run_command("docker", "exec", nexthop, "sh", "-lc", cmd))

    await asyncio.gather(*tasks)


async def start_topology():
    console.print("[bold]Этап 1. Подготовка тестовой топологии сети.[/bold]")
    console.print(
        "Поднимаются генератор трафика (TG-контейнер), испытуемое устройство (DUT-контейнер) и конечные точки (NEXTHOP-контейнеры)."
    )
    await run_command("docker", "compose", "up", "-d", "--build")


async def stop_topology():
    console.print("[bold]Этап 6. Остановка тестовой топологии сети.[/bold]")
    console.print(
        "Останавливаются генератор трафика (TG-контейнер), испытуемое устройство (DUT-контейнер) и конечные точки (NEXTHOP-контейнеры)."
    )
    await run_command("docker", "compose", "down", "--remove-orphans")


def run_analysis(ts: str):
    console.print("[bold]Этап 5. Разбор дампов трафика.[/bold]")
    analyze_pcaps(ts, NEXTHOPS)


async def start():
    try:
        await start_topology()
        ts = await start_capture()
        await generate_traffic()
        await stop_capture()
        run_analysis(ts)
    finally:
        await stop_topology()


if __name__ == "__main__":
    asyncio.run(start())
