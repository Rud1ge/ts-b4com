import asyncio
import subprocess
from datetime import datetime

from rich.console import Console

from scripts.analyze import analyze_distribution, analyze_hash_only_by_source

console = Console()

NEXTHOPS = ["Nexthop-1", "Nexthop-2", "Nexthop-3", "Nexthop-4"]
DESTINATION_IP = "172.16.0.254"
MAX_DEVIATION_PERCENT = 5.0


async def run_command(*args):
    result = subprocess.run(args, check=True, capture_output=True)
    return result


async def docker_exec(container, command):
    return await run_command("docker", "exec", container, "sh", "-lc", command)


def ts_now():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


async def start_topology():
    console.print("[bold]Этап 1. Подготовка тестовой топологии сети.[/bold]")
    console.print("Поднимаются TG, DUT и NEXTHOP-контейнеры.")
    await run_command("docker", "compose", "up", "-d", "--build")


async def stop_topology():
    console.print("[bold]Этап 6. Остановка тестовой топологии сети.[/bold]")
    console.print("Останавливаются TG, DUT и NEXTHOP-контейнеры.")
    await run_command("docker", "compose", "down", "--remove-orphans")


async def start_capture(test_name):
    console.print("[bold]Этап 2. Запуск захвата UDP трафика на NEXTHOP-контейнерах.[/bold]")

    ts = ts_now()
    filt = f"udp and dst host {DESTINATION_IP}"

    tasks = []
    for hop in NEXTHOPS:
        pcap = f"/pcaps/{hop}_{test_name}_{ts}.pcap"
        cmd = (
            f'tcpdump -i eth0 -nn -U -w "{pcap}" "{filt}"'
            f">/tmp/tcpdump_{hop}.log 2>&1 & echo $! > /tmp/tcpdump_{hop}.pid"
        )
        console.print(f"{hop}: захват запущен -> {pcap}")
        tasks.append(docker_exec(hop, cmd))

    await asyncio.gather(*tasks)
    return ts


async def stop_capture():
    console.print("[bold]Этап 4. Остановка захвата трафика.[/bold]")
    await asyncio.gather(*(docker_exec(hop, f"kill -2 $(cat /tmp/tcpdump_{hop}.pid)") for hop in NEXTHOPS))


def run_analysis(ts, test_name):
    console.print("[bold]Этап 5. Разбор дампов трафика.[/bold]")
    if test_name == "distribution":
        return analyze_distribution(ts, NEXTHOPS, MAX_DEVIATION_PERCENT)
    return analyze_hash_only_by_source(ts, NEXTHOPS)


async def generate_in_tg(python_call, ok_msg):
    console.print("[bold]Этап 3. Генерация трафика в TG-контейнере.[/bold]")
    await run_command(
        "docker",
        "exec",
        "Traffic-Generator",
        "python",
        "-c",
        python_call,
    )
    console.print(f"[green]{ok_msg}[/green]")


async def run_test(test_name, python_call, ok_msg):
    ts = await start_capture(test_name)
    await generate_in_tg(python_call, ok_msg)
    await stop_capture()
    run_analysis(ts, test_name)


async def start():
    try:
        await start_topology()
        await run_test(
            "distribution",
            "from scripts.traffic import send_random_sources; send_random_sources()",
            "Traffic-Generator: генерация трафика завершена (случайные Source IP).",
        )

        await run_test(
            "hash-only-source",
            "from scripts.traffic import send_fixed_sources; send_fixed_sources()",
            "Traffic-Generator: генерация трафика завершена (фиксированные Source IP).",
        )
    finally:
        await stop_topology()


if __name__ == "__main__":
    asyncio.run(start())
