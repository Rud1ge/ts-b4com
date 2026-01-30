import re
import subprocess
import time


def main():
    print(
        "Этап 1. Подготовка тестовой топологии сети.\n"
        "Поднимаются генератор трафика (TG-контейнер), испытуемое устройство (DUT-контейнер) и конечные точки (NEXTHOP-контейнеры)."
    )

    subprocess.run(
        ("docker", "compose", "up", "-d", "--build"),
        text=True,
        capture_output=True,
        check=False,
    )

    print("Этап 2. Ожидание установки зависимостей...")
    time.sleep(15)

    print("Этап 3. Запуск захвата трафика на конечных точках.")
    subprocess.run(
        ("docker", "exec", "Nexthop-1", "sh", "-c", "rm -f /tmp/udp_lo_ping.pcap /tmp/tcpdump.pid 2>/dev/null || true"),
        text=True,
        capture_output=True,
        check=False,
    )
    subprocess.run(
        (
            "docker",
            "exec",
            "Nexthop-1",
            "sh",
            "-c",
            "tcpdump -i eth0 -nn 'udp and dst host 172.16.0.254' -w /tmp/udp_lo_ping.pcap >/dev/null 2>&1 & echo $! > /tmp/tcpdump.pid",
        ),
        text=True,
        capture_output=True,
        check=False,
    )

    print("Этап 4. Запуск генерации UDP-трафика на конечную точку.")
    traffic_generator_result = subprocess.run(
        ("docker", "exec", "Traffic-Generator", "python", "/app/scripts/traffic.py"),
        text=True,
        capture_output=True,
        check=False,
    )
    if traffic_generator_result.stdout:
        print(traffic_generator_result.stdout)
    if traffic_generator_result.stderr:
        # TODO: SyntaxWarning убрать
        print(traffic_generator_result.stderr)

    print("Этап 5. Остановка захвата трафика на конечных точках.")
    tcpdump_pid_result = subprocess.run(
        ("docker", "exec", "Nexthop-1", "sh", "-c", "cat /tmp/tcpdump.pid 2>/dev/null"),
        text=True,
        capture_output=True,
        check=False,
    )
    tcpdump_pid = tcpdump_pid_result.stdout.strip()
    if tcpdump_pid:
        subprocess.run(
            ("docker", "exec", "Nexthop-1", "sh", "-c", f"kill -2 {tcpdump_pid} 2>/dev/null || true"),
            text=True,
            capture_output=True,
            check=False,
        )

    time.sleep(1)

    print("Этап 6. Анализ захваченного сетевого трафика.")
    tcpdump_read_result = subprocess.run(
        ("docker", "exec", "Nexthop-1", "sh", "-c", "tcpdump -nn -r /tmp/udp_lo_ping.pcap 2>/dev/null"),
        text=True,
        capture_output=True,
        check=False,
    )

    tcpdump_lines = tcpdump_read_result.stdout.splitlines()

    unique_src_addresses = set()
    src_regex = re.compile(r"\bIP\s+(\d+\.\d+\.\d+\.\d+)\.\d+\s+>\s+172\.16\.0\.254\.\d+:")
    for tcpdump_line in tcpdump_lines:
        match = src_regex.search(tcpdump_line)
        if match:
            unique_src_addresses.add(match.group(1))

    print(f"Захвачено пакетов: {len(tcpdump_lines)}")
    print(f"Захвачено пакетов с уникальным src адресом: {len(unique_src_addresses)}")

    print("Этап 7. Остановка тестовой топологии сети.")
    subprocess.run(
        ("docker", "compose", "down", "-v", "--remove-orphans"),
        text=True,
        capture_output=True,
        check=False,
    )


if __name__ == "__main__":
    main()
