"""
VultronScanner — main.py
=========================
Click-based CLI entry point.

Commands
--------
  scan    Run a full scan against a target
  profiles  List available scan profiles
  version   Show version information

Examples
--------
  python main.py scan --target 192.168.1.1 --profile quick
  python main.py scan --target 10.0.0.0/24 --profile full --dry-run
  python main.py scan --target example.com --profile web
  python main.py profiles
  python main.py --version
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

# Ensure project root is on sys.path when run directly
sys.path.insert(0, str(Path(__file__).parent))

from Core.ConfigLoader import ConfigLoader
from Core.Orchestrator import Orchestrator
from Utils.Logger import LogLevel, configure_root

console = Console()

BANNER = """
 ██╗   ██╗██╗   ██╗██╗  ████████╗██████╗  ██████╗ ███╗   ██╗
 ██║   ██║██║   ██║██║  ╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║
 ██║   ██║██║   ██║██║     ██║   ██████╔╝██║   ██║██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║   ██╔══██╗██║   ██║██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗██║   ██║  ██║╚██████╔╝██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
"""

VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option(version=VERSION, prog_name="VultronScanner")
def cli() -> None:
    """
    \b
    VultronScanner — Modular Attack Surface Manager
    İstinye Üniversitesi · Bilgisayar Mühendisliği Final Projesi

    \b
    ⚠  UYARI: Bu araç YALNIZCA yetkili sistemlerde kullanılmalıdır.
       İzinsiz kullanım yasal suç teşkil eder.
    """
    _print_banner()


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------


@cli.command()
@click.option(
    "--target",
    "-t",
    required=True,
    help="Taranacak IP, CIDR veya hostname (örn: 192.168.1.0/24)",
)
@click.option(
    "--profile",
    "-p",
    default="quick",
    show_default=True,
    help="Tarama profili: quick | full | stealth | web | auth",
)
@click.option(
    "--output-dir",
    "-o",
    default="Reports/Output",
    show_default=True,
    help="Tarama sonuçlarının kaydedileceği dizin",
)
@click.option(
    "--log-level",
    "-l",
    default="INFO",
    show_default=True,
    type=click.Choice(["TRACE", "DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    help="Loglama seviyesi",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Gerçek ağ istekleri göndermeden test çalıştırması yap",
)
@click.option(
    "--save/--no-save",
    default=True,
    show_default=True,
    help="Oturum sonucunu JSON olarak kaydet",
)
def scan(
    target: str,
    profile: str,
    output_dir: str,
    log_level: str,
    dry_run: bool,
    save: bool,
) -> None:
    """
    \b
    Belirtilen hedefe tarama başlatır.

    \b
    Örnekler:
      python main.py scan --target 127.0.0.1 --profile quick --dry-run
      python main.py scan --target 192.168.1.0/24 --profile full
      python main.py scan --target example.com --profile web
    """
    # Resolve log level
    level_map = {
        "TRACE": LogLevel.TRACE,
        "DEBUG": LogLevel.DEBUG,
        "INFO": LogLevel.INFO,
        "WARNING": LogLevel.WARNING,
        "ERROR": LogLevel.ERROR,
    }
    log_dir = Path("logs")
    configure_root(
        level=level_map[log_level.upper()],
        log_dir=log_dir,
        session_id=None,
    )

    # Load config
    try:
        loader = ConfigLoader()
        cfg = loader.load(profile=profile)
    except FileNotFoundError as exc:
        console.print(f"[bold red]Config hatası:[/bold red] {exc}")
        sys.exit(1)

    # Run pipeline
    orchestrator = Orchestrator(cfg)
    try:
        sm = asyncio.run(orchestrator.run(target=target, dry_run=dry_run))
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Tarama kullanıcı tarafından iptal edildi.[/yellow]")
        sys.exit(130)

    # Print summary table
    _print_summary_table(sm.summary())

    # Save session
    if save:
        out_path = sm.save(output_dir=Path(output_dir))
        console.print(f"\n[bright_green]✔ Sonuçlar kaydedildi:[/bright_green] {out_path}")


# ---------------------------------------------------------------------------
# profiles command
# ---------------------------------------------------------------------------


@cli.command()
def profiles() -> None:
    """Kullanılabilir tarama profillerini listele."""
    try:
        loader = ConfigLoader()
        profiles_data = loader.get_profiles_data()
    except FileNotFoundError as exc:
        console.print(f"[red]Config bulunamadı:[/red] {exc}")
        sys.exit(1)

    table = Table(
        title="VultronScanner — Tarama Profilleri",
        show_header=True,
        header_style="bold bright_cyan",
        border_style="dim cyan",
    )
    table.add_column("Profil Key", style="bold yellow", no_wrap=True)
    table.add_column("Ad", style="bright_white")
    table.add_column("Süre", style="dim white")
    table.add_column("Web Analizi", style="green")
    table.add_column("CVE Sorgusu", style="green")
    table.add_column("Brute Force", style="red")

    for key, data in profiles_data.items():
        intel = data.get("modules", {}).get("intelligence", {})
        action = data.get("modules", {}).get("action", {})
        table.add_row(
            key,
            data.get("name", key),
            data.get("estimated_duration", "—"),
            "✔" if intel.get("web_analyzer") else "✗",
            "✔" if intel.get("vulnerability_engine") else "✗",
            "✔" if action.get("brute_force") else "✗",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _print_banner() -> None:
    console.print(f"[bright_cyan]{BANNER}[/bright_cyan]")
    console.print(f"  [dim]v{VERSION} · İstinye Üniversitesi · Bilgisayar Mühendisliği[/dim]\n")


def _print_summary_table(summary: dict) -> None:
    table = Table(
        title="Tarama Özeti",
        show_header=True,
        header_style="bold bright_cyan",
        border_style="cyan",
    )
    table.add_column("Metrik", style="bold white", no_wrap=True)
    table.add_column("Değer", style="bright_yellow")

    elapsed = summary.get("elapsed_sec") or 0
    risk = summary.get("risk_breakdown", {})

    rows = [
        ("Oturum ID", summary.get("session_id", "—")[:16] + "..."),
        ("Hedef", summary.get("target", "—")),
        ("Profil", summary.get("profile", "—")),
        ("Durum", summary.get("state", "—")),
        ("Geçen Süre", f"{elapsed:.1f} saniye"),
        ("Toplam Host", str(summary.get("total_hosts", 0))),
        ("Aktif Host", str(summary.get("alive_hosts", 0))),
        ("Açık Port", str(summary.get("open_ports", 0))),
        ("Hata Sayısı", str(summary.get("errors", 0))),
        ("─" * 20, "─" * 10),
        ("CRITICAL risk", str(risk.get("CRITICAL", 0))),
        ("HIGH risk", str(risk.get("HIGH", 0))),
        ("MEDIUM risk", str(risk.get("MEDIUM", 0))),
        ("LOW risk", str(risk.get("LOW", 0))),
    ]

    for label, value in rows:
        table.add_row(label, value)

    console.print()
    console.print(table)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
