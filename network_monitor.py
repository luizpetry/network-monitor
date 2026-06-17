"""
Network Monitor - Real-time network packet capture and analysis tool.

Captures packets via Scapy, displays a live table of traffic with statistics
(packets per protocol, top talkers), supports protocol filtering and logging.

Requires:
    - Python 3.8+
    - Npcap installed (https://npcap.com/)
    - Administrator privileges on Windows
    - Packages from requirements.txt (scapy, rich)

Usage examples:
    python network_monitor.py
    python network_monitor.py --protocol tcp
    python network_monitor.py --protocol udp --log traffic.log
    python network_monitor.py --iface "Ethernet" --max-rows 25
    python network_monitor.py --list-ifaces
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import signal
import sys
import threading
import time
import urllib.parse
import urllib.request
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import Deque, Dict, Optional, Set

# Silence Scapy IPv6 / runtime warnings before import noise hits the terminal
os.environ.setdefault("PYTHONWARNINGS", "ignore")

try:
    from scapy.all import sniff, conf, get_if_list  # type: ignore
    from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.packet import Packet  # type: ignore
except ImportError as exc:  # pragma: no cover
    print("ERROR: scapy is not installed. Run: pip install -r requirements.txt")
    print(f"Detail: {exc}")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError as exc:  # pragma: no cover
    print("ERROR: rich is not installed. Run: pip install -r requirements.txt")
    print(f"Detail: {exc}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# AbuseIPDB checker
# ---------------------------------------------------------------------------

# Ranges de provedores conhecidos e confiáveis — ignorados na verificação
_TRUSTED_NETWORKS = [ipaddress.ip_network(n, strict=False) for n in [
    # Google
    "8.8.8.0/24", "8.8.4.0/24", "142.250.0.0/15", "172.217.0.0/16",
    "216.58.192.0/19", "64.233.160.0/19", "74.125.0.0/16",
    "2001:4860::/32",
    # Cloudflare
    "1.1.1.0/24", "1.0.0.0/24", "104.16.0.0/13", "104.24.0.0/14",
    "172.64.0.0/13", "131.0.72.0/22", "2606:4700::/32",
    # Microsoft / Azure
    "13.64.0.0/11", "13.96.0.0/13", "13.104.0.0/14", "20.0.0.0/8",
    "40.64.0.0/10", "52.0.0.0/8", "104.40.0.0/13", "2603:1000::/24",
    "2603:1010::/25", "2603:1020::/25", "2603:1030::/25", "2603:1040::/25",
    "2603:1050::/25", "2603:1056::/26",
    # Amazon AWS (52.0.0.0/8 já coberto acima pela Azure)
    "54.0.0.0/8", "3.0.0.0/8",
    # Akamai
    "23.0.0.0/8", "104.64.0.0/10",
    # Meta / Facebook
    "157.240.0.0/17", "179.60.192.0/22", "31.13.24.0/21",
]]


class AbuseIPChecker:
    """Background IP reputation checker using AbuseIPDB v2 API. Thread-safe."""

    API_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str, max_age_days: int = 30) -> None:
        self.api_key = api_key
        self.max_age_days = max_age_days
        self._cache: Dict[str, Optional[int]] = {}
        self._pending: Set[str] = set()
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="abuseip")

    def _should_skip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return True
            for network in _TRUSTED_NETWORKS:
                if addr in network:
                    return True
            return False
        except ValueError:
            return True

    def get_score(self, ip: str) -> Optional[int]:
        with self._lock:
            return self._cache.get(ip)

    def is_pending(self, ip: str) -> bool:
        with self._lock:
            return ip in self._pending

    def enqueue(self, ip: str) -> None:
        if not ip or self._should_skip(ip):
            return
        with self._lock:
            if ip in self._cache or ip in self._pending:
                return
            self._pending.add(ip)
        self._executor.submit(self._check_ip, ip)

    def _check_ip(self, ip: str) -> None:
        score = None
        try:
            params = urllib.parse.urlencode({
                "ipAddress": ip,
                "maxAgeInDays": str(self.max_age_days),
            })
            req = urllib.request.Request(f"{self.API_URL}?{params}")
            req.add_header("Key", self.api_key)
            req.add_header("Accept", "application/json")
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())
                score = int(data["data"]["abuseConfidenceScore"])
        except Exception:
            pass
        with self._lock:
            self._cache[ip] = score
            self._pending.discard(ip)

    def snapshot(self) -> Dict[str, Optional[int]]:
        """Returns a copy of all checked IPs and their scores. Thread-safe."""
        with self._lock:
            return dict(self._cache)

    def fetch_details(self, ip: str) -> Optional[dict]:
        """Fetch the full AbuseIPDB report for a single IP (verbose, with reports).

        Returns the API 'data' object, or None on failure.
        """
        try:
            params = urllib.parse.urlencode({
                "ipAddress": ip,
                "maxAgeInDays": str(self.max_age_days),
                "verbose": "",
            })
            req = urllib.request.Request(f"{self.API_URL}?{params}")
            req.add_header("Key", self.api_key)
            req.add_header("Accept", "application/json")
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                return data.get("data")
        except Exception:
            return None

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False)

    def flagged_ips(self, threshold: int = 1) -> list:
        """Returns list of (ip, score) with score >= threshold, sorted by score desc."""
        with self._lock:
            return sorted(
                [(ip, s) for ip, s in self._cache.items() if s is not None and s >= threshold],
                key=lambda x: x[1],
                reverse=True,
            )


def _format_abuse_score(score: Optional[int], pending: bool) -> Text:
    if pending:
        return Text("...", style="dim")
    if score is None:
        return Text("-", style="dim")
    if score == 0:
        return Text("0", style="green")
    if score < 25:
        return Text(str(score), style="yellow")
    if score < 75:
        return Text(str(score), style="bold yellow")
    return Text(str(score), style="bold red")


# AbuseIPDB report category IDs -> human-readable names
ABUSE_CATEGORIES: Dict[int, str] = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
    11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted",
}


def _categories_label(ids: list) -> str:
    names = [ABUSE_CATEGORIES.get(int(c), str(c)) for c in (ids or [])]
    return ", ".join(names) if names else "-"


# Substrings (lowercase) of ISPs/orgs reconhecidamente reputáveis. Um IP cujo
# ISP bate com algum destes raramente é uma ameaça real — reforça falso positivo.
_REPUTABLE_ISPS = [
    "google", "cloudflare", "amazon", "aws", "microsoft", "azure",
    "akamai", "meta", "facebook", "new relic", "fastly", "apple",
    "oracle", "digitalocean", "linode", "github", "gitlab",
]


def _is_reputable_isp(isp: str) -> bool:
    low = (isp or "").lower()
    return any(name in low for name in _REPUTABLE_ISPS)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class PacketRecord:
    """Lightweight summary of a single captured packet."""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    info: str = ""

    def as_log_row(self) -> list:
        return [
            self.timestamp.isoformat(timespec="milliseconds"),
            self.protocol,
            self.src_ip,
            self.src_port if self.src_port is not None else "",
            self.dst_ip,
            self.dst_port if self.dst_port is not None else "",
            self.length,
            self.info,
        ]


@dataclass
class Stats:
    """Aggregated counters used to render statistics panels."""
    total_packets: int = 0
    total_bytes: int = 0
    by_protocol: Counter = field(default_factory=Counter)
    by_src_ip: Counter = field(default_factory=Counter)
    by_dst_ip: Counter = field(default_factory=Counter)
    by_dst_port: Counter = field(default_factory=Counter)
    started_at: float = field(default_factory=time.time)

    def update(self, rec: PacketRecord) -> None:
        self.total_packets += 1
        self.total_bytes += rec.length
        self.by_protocol[rec.protocol] += 1
        if rec.src_ip:
            self.by_src_ip[rec.src_ip] += 1
        if rec.dst_ip:
            self.by_dst_ip[rec.dst_ip] += 1
        if rec.dst_port is not None:
            self.by_dst_port[rec.dst_port] += 1

    @property
    def elapsed_seconds(self) -> float:
        return max(time.time() - self.started_at, 0.001)

    @property
    def pps(self) -> float:
        return self.total_packets / self.elapsed_seconds


# ---------------------------------------------------------------------------
# Packet parsing
# ---------------------------------------------------------------------------

PROTOCOL_COLORS = {
    "TCP": "cyan",
    "UDP": "magenta",
    "ICMP": "yellow",
    "ICMPv6": "yellow",
    "IPv6": "blue",
    "ARP": "green",
    "OTHER": "white",
}


def parse_packet(pkt: Packet) -> Optional[PacketRecord]:
    """Convert a Scapy packet into a PacketRecord (or None if irrelevant)."""
    try:
        length = len(pkt)
        src_ip = ""
        dst_ip = ""
        proto = "OTHER"
        sport: Optional[int] = None
        dport: Optional[int] = None
        info = ""

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            proto = "IPv6"

        if TCP in pkt:
            proto = "TCP"
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            flags = pkt[TCP].flags
            info = f"flags={flags}"
        elif UDP in pkt:
            proto = "UDP"
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
        elif ICMP in pkt:
            proto = "ICMP"
            info = f"type={pkt[ICMP].type}"
        elif pkt.haslayer("ARP"):
            proto = "ARP"
            arp = pkt["ARP"]
            src_ip = getattr(arp, "psrc", "")
            dst_ip = getattr(arp, "pdst", "")
            info = f"op={getattr(arp, 'op', '')}"

        if not src_ip and not dst_ip and proto == "OTHER":
            # Skip frames we cannot meaningfully describe (e.g. raw L2 noise)
            return None

        return PacketRecord(
            timestamp=datetime.now(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=proto,
            src_port=sport,
            dst_port=dport,
            length=length,
            info=info,
        )
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Logging sink
# ---------------------------------------------------------------------------

class CSVLogger:
    """Append-only CSV writer for captured packets. Thread-safe."""

    HEADER = ["timestamp", "protocol", "src_ip", "src_port",
              "dst_ip", "dst_port", "length", "info"]

    # Flush in batches to avoid one fsync per packet under heavy traffic.
    FLUSH_EVERY = 50

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._since_flush = 0
        new_file = not os.path.exists(path)
        # newline="" is required for csv on Windows to avoid blank lines
        self._fh = open(path, "a", newline="", encoding="utf-8")
        self._writer = csv.writer(self._fh)
        if new_file:
            self._writer.writerow(self.HEADER)
            self._fh.flush()

    def write(self, rec: PacketRecord) -> None:
        with self._lock:
            self._writer.writerow(rec.as_log_row())
            self._since_flush += 1
            if self._since_flush >= self.FLUSH_EVERY:
                self._fh.flush()
                self._since_flush = 0

    def close(self) -> None:
        with self._lock:
            try:
                self._fh.flush()
                self._fh.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Monitor (capture + render coordinator)
# ---------------------------------------------------------------------------

class NetworkMonitor:
    def __init__(
        self,
        iface: Optional[str],
        bpf_filter: Optional[str],
        max_rows: int,
        logger: Optional[CSVLogger],
        checker: Optional[AbuseIPChecker] = None,
    ) -> None:
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.max_rows = max_rows
        self.logger = logger
        self.checker = checker

        self.recent: Deque[PacketRecord] = deque(maxlen=max_rows)
        self.stats = Stats()
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self.console = Console()

    # ----- capture thread -----
    def _on_packet(self, pkt: Packet) -> None:
        rec = parse_packet(pkt)
        if rec is None:
            return
        with self._lock:
            self.recent.appendleft(rec)
            self.stats.update(rec)
        if self.logger is not None:
            self.logger.write(rec)
        if self.checker is not None:
            self.checker.enqueue(rec.src_ip)
            self.checker.enqueue(rec.dst_ip)

    def _capture_loop(self) -> None:
        try:
            sniff(
                iface=self.iface,
                filter=self.bpf_filter,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _p: self._stop_event.is_set(),
            )
        except PermissionError:
            self.console.print(
                "[red]Permission denied. Run this terminal as Administrator.[/red]"
            )
            self._stop_event.set()
        except OSError as exc:
            self.console.print(
                f"[red]Capture error: {exc}.\n"
                f"Verify Npcap is installed and the interface name is correct.[/red]"
            )
            self._stop_event.set()
        except Exception as exc:  # pragma: no cover
            self.console.print(f"[red]Unexpected capture error: {exc}[/red]")
            self._stop_event.set()

    # ----- render -----
    def _render_packets_table(self) -> Table:
        table = Table(
            title="Live packets (most recent first)",
            expand=True,
            header_style="bold white on dark_blue",
        )
        table.add_column("Time", style="dim", width=12, no_wrap=True)
        table.add_column("Proto", width=7)
        table.add_column("Source", overflow="fold")
        table.add_column("S.Port", justify="right", width=6)
        table.add_column("Destination", overflow="fold")
        table.add_column("D.Port", justify="right", width=6)
        table.add_column("Bytes", justify="right", width=7)
        if self.checker is not None:
            table.add_column("Abuse%", justify="right", width=7)
        table.add_column("Info", overflow="fold")

        with self._lock:
            snapshot = list(self.recent)

        for rec in snapshot:
            color = PROTOCOL_COLORS.get(rec.protocol, "white")
            row = [
                rec.timestamp.strftime("%H:%M:%S.%f")[:-3],
                Text(rec.protocol, style=color),
                rec.src_ip or "-",
                str(rec.src_port) if rec.src_port is not None else "-",
                rec.dst_ip or "-",
                str(rec.dst_port) if rec.dst_port is not None else "-",
                str(rec.length),
            ]
            if self.checker is not None:
                src_score = self.checker.get_score(rec.src_ip)
                score = src_score if src_score is not None else self.checker.get_score(rec.dst_ip)
                pending = (
                    self.checker.is_pending(rec.src_ip)
                    or self.checker.is_pending(rec.dst_ip)
                )
                row.append(_format_abuse_score(score, pending))
            row.append(rec.info)
            table.add_row(*row)
        return table

    def _render_stats_panel(self) -> Panel:
        with self._lock:
            total = self.stats.total_packets
            total_bytes = self.stats.total_bytes
            elapsed = self.stats.elapsed_seconds
            pps = self.stats.pps
            top_proto = self.stats.by_protocol.most_common(6)
            top_src = self.stats.by_src_ip.most_common(5)
            top_dst = self.stats.by_dst_ip.most_common(5)
            top_port = self.stats.by_dst_port.most_common(5)

        proto_table = Table.grid(padding=(0, 2))
        proto_table.add_column("Protocol", style="bold")
        proto_table.add_column("Count", justify="right")
        for name, count in top_proto:
            color = PROTOCOL_COLORS.get(name, "white")
            proto_table.add_row(Text(name, style=color), str(count))
        if not top_proto:
            proto_table.add_row("(no data yet)", "")

        src_table = Table.grid(padding=(0, 2))
        src_table.add_column("Top sources", style="bold")
        src_table.add_column("Count", justify="right")
        for ip, count in top_src:
            src_table.add_row(ip, str(count))
        if not top_src:
            src_table.add_row("(no data yet)", "")

        dst_table = Table.grid(padding=(0, 2))
        dst_table.add_column("Top destinations", style="bold")
        dst_table.add_column("Count", justify="right")
        for ip, count in top_dst:
            dst_table.add_row(ip, str(count))
        if not top_dst:
            dst_table.add_row("(no data yet)", "")

        port_table = Table.grid(padding=(0, 2))
        port_table.add_column("Top dest ports", style="bold")
        port_table.add_column("Count", justify="right")
        for port, count in top_port:
            port_table.add_row(str(port), str(count))
        if not top_port:
            port_table.add_row("(no data yet)", "")

        summary = Text()
        summary.append("Packets: ", style="bold")
        summary.append(f"{total}   ")
        summary.append("Bytes: ", style="bold")
        summary.append(f"{total_bytes}   ")
        summary.append("Rate: ", style="bold")
        summary.append(f"{pps:.1f} pkt/s   ")
        summary.append("Elapsed: ", style="bold")
        summary.append(f"{elapsed:.0f}s")

        flagged_table = Table.grid(padding=(0, 2))
        flagged_table.add_column("Malicious IPs", style="bold")
        flagged_table.add_column("Score", justify="right")
        if self.checker is not None:
            flagged = self.checker.flagged_ips(threshold=1)[:5]
            if flagged:
                for ip, score in flagged:
                    flagged_table.add_row(
                        Text(ip, style="bold red" if score >= 75 else "yellow"),
                        _format_abuse_score(score, False),
                    )
            else:
                flagged_table.add_row(Text("(none detected)", style="green"), "")
        else:
            flagged_table.add_row("(disabled)", "")

        outer = Table.grid(expand=True)
        outer.add_column(ratio=1)
        outer.add_column(ratio=1)
        outer.add_column(ratio=1)
        outer.add_column(ratio=1)
        outer.add_column(ratio=1)
        outer.add_row(proto_table, src_table, dst_table, port_table, flagged_table)

        body = Table.grid(expand=True)
        body.add_row(summary)
        body.add_row(outer)
        return Panel(body, title="Statistics", border_style="green")

    def _render_header(self) -> Panel:
        iface_label = self.iface or "(default)"
        filt_label = self.bpf_filter or "none"
        log_label = self.logger.path if self.logger else "disabled"
        text = Text()
        text.append("Network Monitor", style="bold white")
        text.append("   Interface: ", style="dim")
        text.append(iface_label, style="bold")
        text.append("   Filter: ", style="dim")
        text.append(filt_label, style="bold")
        text.append("   Log: ", style="dim")
        text.append(log_label, style="bold")
        text.append("   (Ctrl+C to stop)", style="dim")
        return Panel(text, border_style="blue")

    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="stats", size=10),
            Layout(name="packets", ratio=1),
        )
        layout["header"].update(self._render_header())
        layout["stats"].update(self._render_stats_panel())
        layout["packets"].update(self._render_packets_table())
        return layout

    # ----- run -----
    def run(self) -> None:
        capture_thread = threading.Thread(
            target=self._capture_loop, name="capture", daemon=True
        )
        capture_thread.start()

        try:
            with Live(
                self._build_layout(),
                console=self.console,
                refresh_per_second=4,
                screen=False,
            ) as live:
                while not self._stop_event.is_set():
                    live.update(self._build_layout())
                    time.sleep(0.25)
        except KeyboardInterrupt:
            pass
        finally:
            self._stop_event.set()
            capture_thread.join(timeout=2.0)
            if self.logger is not None:
                self.logger.close()
            self._print_final_summary()
            self._interactive_ip_lookup()
            if self.checker is not None:
                self.checker.shutdown()

    def _print_final_summary(self) -> None:
        self.console.rule("[bold]Final summary[/bold]")
        self.console.print(f"Total packets captured: [bold]{self.stats.total_packets}[/bold]")
        self.console.print(f"Total bytes:            [bold]{self.stats.total_bytes}[/bold]")
        self.console.print(f"Elapsed:                [bold]{self.stats.elapsed_seconds:.1f}s[/bold]")

        if self.stats.by_protocol:
            self.console.print("Protocol breakdown:")
            for name, count in self.stats.by_protocol.most_common():
                self.console.print(f"  {name:<8} {count}")

        if self.checker is not None:
            self.console.rule("[bold]IP Reputation Report (AbuseIPDB)[/bold]")
            all_checked = self.checker.snapshot()

            if not all_checked:
                self.console.print("[dim]Nenhum IP externo verificado.[/dim]")
            else:
                table = Table(
                    title=f"IPs verificados: {len(all_checked)}",
                    header_style="bold white on dark_blue",
                    show_lines=False,
                )
                table.add_column("IP", overflow="fold")
                table.add_column("Score", justify="center", width=8)
                table.add_column("Reputação", width=20)

                sorted_ips = sorted(
                    all_checked.items(),
                    key=lambda x: (x[1] is None, -(x[1] or 0)),
                )
                for ip, score in sorted_ips:
                    if score is None:
                        score_text = Text("?", style="dim")
                        label = Text("Erro na consulta", style="dim")
                    elif score == 0:
                        score_text = Text("0", style="green")
                        label = Text("Limpo", style="green")
                    elif score < 25:
                        score_text = Text(str(score), style="yellow")
                        label = Text("Baixo risco", style="yellow")
                    elif score < 75:
                        score_text = Text(str(score), style="bold yellow")
                        label = Text("Risco medio", style="bold yellow")
                    else:
                        score_text = Text(str(score), style="bold red")
                        label = Text("MALICIOSO", style="bold red")

                    table.add_row(ip, score_text, label)

                self.console.print(table)

                flagged = [(ip, s) for ip, s in all_checked.items() if s is not None and s > 0]
                if flagged:
                    self.console.print(
                        f"[bold red]Atenção:[/bold red] {len(flagged)} IP(s) com score > 0 detectado(s)."
                    )
                else:
                    self.console.print("[green]Nenhum IP malicioso detectado na sessão.[/green]")

        if self.logger is not None:
            self.console.print(f"Log written to: [bold]{self.logger.path}[/bold]")

    # ----- interactive drill-down -----
    def _interactive_ip_lookup(self) -> None:
        """After the summary, let the user inspect any IP in detail (AbuseIPDB)."""
        if self.checker is None:
            return
        if not sys.stdin or not sys.stdin.isatty():
            return  # no interactive terminal (e.g. piped/redirected)

        checked = self.checker.snapshot()
        self.console.rule("[bold]Verificação detalhada de IP[/bold]")
        self.console.print(
            "Digite um IP para ver os detalhes completos no AbuseIPDB "
            "(ISP, país, denúncias...).\n"
            "Pressione [bold]Enter[/bold] vazio para sair."
        )
        if checked:
            self.console.print(
                f"[dim]IPs verificados nesta sessão: "
                f"{', '.join(sorted(checked.keys()))}[/dim]"
            )

        while True:
            try:
                choice = input("\nIP> ").strip()
            except (EOFError, KeyboardInterrupt):
                self.console.print()
                return
            if not choice:
                return
            try:
                ipaddress.ip_address(choice)
            except ValueError:
                self.console.print(f"[yellow]'{choice}' não é um IP válido.[/yellow]")
                continue

            self.console.print(f"[dim]Consultando {choice}...[/dim]")
            data = self.checker.fetch_details(choice)
            if not data:
                self.console.print(
                    "[red]Falha na consulta. Verifique a chave da API e a conexão.[/red]"
                )
                continue
            self._render_ip_details(data)

    def _render_ip_details(self, data: dict) -> None:
        score = int(data.get("abuseConfidenceScore", 0) or 0)
        if score == 0:
            border, verdict = "green", Text("Limpo", style="green")
        elif score < 25:
            border, verdict = "yellow", Text("Baixo risco", style="yellow")
        elif score < 75:
            border, verdict = "yellow", Text("Risco médio", style="bold yellow")
        else:
            border, verdict = "red", Text("MALICIOSO", style="bold red")

        hostnames = data.get("hostnames") or []
        flags = []
        if data.get("isTor"):
            flags.append("Tor")
        if data.get("isWhitelisted"):
            flags.append("Whitelisted")

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold cyan", justify="right")
        grid.add_column()
        grid.add_row("IP:", str(data.get("ipAddress", "-")))
        grid.add_row("Score:", _format_abuse_score(score, False))
        grid.add_row("Veredito:", verdict)
        grid.add_row("País:", str(data.get("countryName") or data.get("countryCode") or "-"))
        grid.add_row("ISP:", str(data.get("isp") or "-"))
        grid.add_row("Domínio:", str(data.get("domain") or "-"))
        grid.add_row("Tipo de uso:", str(data.get("usageType") or "-"))
        grid.add_row("Hostnames:", ", ".join(hostnames) if hostnames else "-")
        grid.add_row("Total de denúncias:", str(data.get("totalReports", 0)))
        grid.add_row("Usuários distintos:", str(data.get("numDistinctUsers", 0)))
        grid.add_row("Última denúncia:", str(data.get("lastReportedAt") or "-"))
        if flags:
            grid.add_row("Flags:", Text(", ".join(flags), style="bold magenta"))

        self.console.print(
            Panel(grid, title=f"Detalhes — {data.get('ipAddress', '')}",
                  border_style=border)
        )

        reports = data.get("reports") or []
        if reports:
            rtable = Table(
                title=f"Denúncias recentes (mostrando {min(len(reports), 5)} de {len(reports)})",
                header_style="bold white on dark_blue",
            )
            rtable.add_column("Data", width=20, no_wrap=True)
            rtable.add_column("Categorias")
            rtable.add_column("Comentário", overflow="fold")
            for rep in reports[:5]:
                comment = (rep.get("comment") or "").strip().replace("\n", " ")
                if len(comment) > 120:
                    comment = comment[:117] + "..."
                rtable.add_row(
                    str(rep.get("reportedAt", "-")),
                    _categories_label(rep.get("categories")),
                    comment or "-",
                )
            self.console.print(rtable)

        self.console.print(self._interpretation_panel(score, data))

    def _interpretation_panel(self, score: int, data: dict) -> Panel:
        """Plain-language guidance on how to read the score for this IP."""
        isp = str(data.get("isp") or "")
        note = Text()
        if score == 0:
            note.append("Sem denúncias relevantes. ", style="bold green")
            note.append("IP considerado limpo pelo AbuseIPDB.")
        elif score < 25:
            note.append("Score baixo — frequentemente é FALSO POSITIVO.\n", style="bold yellow")
            note.append(
                "Honeypots e firewalls domésticos (MikroTik, UFW...) denunciam "
                "automaticamente qualquer conexão inesperada, inclusive tráfego de "
                "resposta legítimo. Se o ISP é uma empresa conhecida (Google, "
                "Cloudflare, AWS, New Relic...), quase sempre é benigno."
            )
        elif score < 75:
            note.append("Risco moderado — vale investigar.\n", style="bold yellow")
            note.append(
                "Olhe as categorias e os comentários das denúncias acima e confira "
                "o ISP. Padrão repetido de Hacking/Brute-Force/Port Scan vindo de um "
                "ISP obscuro merece atenção; ISP conhecido tende a ser ruído."
            )
        else:
            note.append("Score alto — trate como potencialmente malicioso.\n", style="bold red")
            note.append(
                "Se as categorias mostram Hacking, SSH, Brute-Force ou Web App Attack "
                "de forma repetida e o ISP é desconhecido, considere bloquear esse IP "
                "no firewall."
            )
        # --- Sinais automáticos ---
        total = int(data.get("totalReports", 0) or 0)
        users = int(data.get("numDistinctUsers", 0) or 0)

        if _is_reputable_isp(isp):
            note.append("\n\n• ISP reconhecido como provedor reputável", style="bold green")
            note.append(
                " — reforça que provavelmente é tráfego legítimo / falso positivo.",
                style="green",
            )

        # Denúncias concentradas: muitas denúncias vindas de pouquíssimos denunciantes.
        if total >= 5 and users > 0 and total / users >= 4:
            note.append("\n\n• Denúncias concentradas", style="bold cyan")
            note.append(
                f" — {total} denúncias de apenas {users} denunciante(s) "
                f"(~{total / users:.0f} por pessoa). Poucos denunciantes "
                "repetindo costuma indicar ruído de honeypot, não ameaça ampla.",
                style="cyan",
            )

        if isp:
            note.append(f"\n\nISP deste IP: ", style="dim")
            note.append(isp, style="bold")
        return Panel(note, title="Como interpretar", border_style="cyan")


# ---------------------------------------------------------------------------
# CLI plumbing
# ---------------------------------------------------------------------------

PROTOCOL_TO_BPF: Dict[str, str] = {
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "icmp6": "icmp6",
    "arp": "arp",
    "ip": "ip",
    "ipv6": "ip6",
}


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="network_monitor",
        description="Real-time network monitor (Scapy + Rich).",
    )
    p.add_argument(
        "--iface",
        help="Network interface name. On Windows use the friendly name "
             "(e.g. 'Wi-Fi', 'Ethernet') or the NPF GUID. "
             "Use --list-ifaces to see options.",
    )
    p.add_argument(
        "--protocol",
        choices=sorted(PROTOCOL_TO_BPF.keys()),
        help="Filter by protocol (translates to a BPF filter).",
    )
    p.add_argument(
        "--filter",
        dest="bpf",
        help="Custom BPF filter (overrides --protocol). Example: 'port 53'.",
    )
    p.add_argument(
        "--log",
        help="Path to CSV log file. Created if missing, appended otherwise.",
    )
    p.add_argument(
        "--max-rows",
        type=int,
        default=20,
        help="Maximum number of recent packets to display (default: 20).",
    )
    p.add_argument(
        "--list-ifaces",
        action="store_true",
        help="List available network interfaces and exit.",
    )
    p.add_argument(
        "--abuseipdb-key",
        default=os.environ.get("ABUSEIPDB_KEY", ""),
        help="AbuseIPDB API key for IP reputation checks. "
             "Defaults to the ABUSEIPDB_KEY environment variable.",
    )
    p.add_argument(
        "--no-abuse-check",
        action="store_true",
        help="Disable AbuseIPDB reputation checks.",
    )
    return p


def list_interfaces(console: Console) -> None:
    table = Table(title="Available interfaces", header_style="bold white on dark_blue")
    table.add_column("Name")
    table.add_column("Description")
    try:
        ifaces = conf.ifaces  # type: ignore[attr-defined]
        for name, data in ifaces.items():
            description = getattr(data, "description", "") or getattr(data, "name", "")
            table.add_row(str(name), str(description))
    except Exception:
        for name in get_if_list():
            table.add_row(str(name), "")
    console.print(table)


def resolve_filter(args: argparse.Namespace) -> Optional[str]:
    if args.bpf:
        return args.bpf
    if args.protocol:
        return PROTOCOL_TO_BPF[args.protocol]
    return None


def load_dotenv(path: Optional[str] = None) -> None:
    """Minimal .env loader (no dependency). Only sets vars not already in env."""
    if path is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except FileNotFoundError:
        pass


def main() -> int:
    load_dotenv()
    parser = build_arg_parser()
    args = parser.parse_args()
    console = Console()

    if args.list_ifaces:
        list_interfaces(console)
        return 0

    bpf_filter = resolve_filter(args)
    logger = CSVLogger(args.log) if args.log else None
    checker: Optional[AbuseIPChecker] = None
    if not args.no_abuse_check and args.abuseipdb_key:
        checker = AbuseIPChecker(api_key=args.abuseipdb_key)
        console.print("[dim]AbuseIPDB reputation checks enabled.[/dim]")

    # Graceful Ctrl+C on Windows when running inside some terminals
    def _sigint(_signum, _frame):
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGINT, _sigint)
    except Exception:
        pass

    monitor = NetworkMonitor(
        iface=args.iface,
        bpf_filter=bpf_filter,
        max_rows=max(5, args.max_rows),
        logger=logger,
        checker=checker,
    )
    monitor.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
