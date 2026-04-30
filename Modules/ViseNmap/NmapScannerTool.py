"""
Modules.ViseNmap.NmapScannerTool
==================================
Vize projesi Nmap tarayıcısının VultronScanner mimarisine
entegre edilmiş adaptör sınıfı.

Bu modül iki katmandan oluşur:
    1. NmapScannerTool: VultronScanner tarafından çağrılan ana sınıf.
       scan() metodu, Finding listesi döndürür.

    2. _NmapCore: Gerçek Nmap komutu veya python-nmap kütüphanesi
       ile port taramasını gerçekleştirir.

Vize Kodunu Entegre Etmek İçin:
    Kendi vize proje dosyalarınızı bu klasöre kopyalayın ve
    _NmapCore sınıfını kendi implementasyonunuz ile değiştirin
    ya da miras alın:

    Örnek:
        from Modules.ViseNmap.vize_kaynak_dosyan import VizeNmapClass
        class _NmapCore(VizeNmapClass):
            ...

Severity Mantığı:
    - Açık port (standart risk servis → Medium)
    - Kritik servisler (21/FTP, 23/Telnet, 445/SMB → High/Critical)
    - Bilinen zafiyet portları (3389/RDP, 5900/VNC → High)

Yazar   : VultronScanner Team
Sürüm   : 1.0.0
Ders    : BGT006 Sızma Testi — İstinye Üniversitesi
"""

from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from typing import NamedTuple

from Core.Models import Finding, Severity


# ── Port Risk Tanımları ────────────────────────────────────────────────────────

class _PortRisk(NamedTuple):
    severity: Severity
    service: str
    description: str
    recommendation: str


# Yüksek riskli port veritabanı
_HIGH_RISK_PORTS: dict[int, _PortRisk] = {
    21:   _PortRisk(Severity.HIGH,     "FTP",         "FTP servisi açık. Kimlik bilgileri şifresiz iletilir.",           "FTP yerine SFTP/SCP kullanın. Gerekli değilse kapatın."),
    23:   _PortRisk(Severity.CRITICAL, "Telnet",      "Telnet servisi açık. Tüm trafik düz metin iletilir.",             "Telnet'i devre dışı bırakın, SSH kullanın."),
    25:   _PortRisk(Severity.MEDIUM,   "SMTP",        "SMTP servisi açık. Open relay riski olabilir.",                   "SMTP kimlik doğrulamasını zorunlu kılın, relay kısıtlaması ekleyin."),
    53:   _PortRisk(Severity.LOW,      "DNS",         "DNS servisi dışa açık.",                                          "DNS sorgularını iç ağ ile sınırlandırın, recursive sorguyu kapatın."),
    80:   _PortRisk(Severity.LOW,      "HTTP",        "Şifresiz HTTP servisi açık.",                                     "HTTPS'e yönlendirin, HTTP'yi devre dışı bırakın."),
    110:  _PortRisk(Severity.MEDIUM,   "POP3",        "POP3 servisi açık, şifresiz bağlantı riski.",                     "POP3S (995) kullanın veya IMAP/SSL tercih edin."),
    135:  _PortRisk(Severity.HIGH,     "MSRPC",       "Microsoft RPC servisi açık. Uzaktan saldırılara karşı savunmasız.", "Güvenlik duvarında 135/TCP erişimini kısıtlayın."),
    139:  _PortRisk(Severity.HIGH,     "NetBIOS",     "NetBIOS servisi açık. SMB saldırılarına zemin hazırlar.",          "NetBIOS'u devre dışı bırakın, SMB imzalamasını aktif edin."),
    445:  _PortRisk(Severity.CRITICAL, "SMB",         "SMB servisi açık. EternalBlue (MS17-010) gibi kritik açıklar.",   "SMBv1'i devre dışı bırakın, yamaları uygulayın, güvenlik duvarında kısıtlayın."),
    1433: _PortRisk(Severity.HIGH,     "MSSQL",       "Microsoft SQL Server dışa açık.",                                 "SQL Server'ı sadece localhost'a bağlayın veya VPN arkasına alın."),
    1521: _PortRisk(Severity.HIGH,     "Oracle DB",   "Oracle veritabanı dışa açık.",                                    "Veritabanı portunu güvenlik duvarı ile koruyun."),
    2222: _PortRisk(Severity.MEDIUM,   "SSH (alt.)",  "SSH alternatif portta çalışıyor.",                                "Anahtar tabanlı kimlik doğrulama kullanın, parola girişini kapatın."),
    3306: _PortRisk(Severity.HIGH,     "MySQL",       "MySQL dışa açık.",                                                "MySQL'i localhost'a bağlayın, uzak erişimi engelleyin."),
    3389: _PortRisk(Severity.HIGH,     "RDP",         "Uzak Masaüstü Protokolü açık. Brute-force ve BlueKeep riski.",    "RDP'yi VPN arkasına alın, NLA'yı zorunlu kılın, güvenlik duvarında kısıtlayın."),
    4444: _PortRisk(Severity.CRITICAL, "Metasploit",  "Port 4444 açık — varsayılan Metasploit listener portu.",          "Bu portu acilen kapatın ve sistem güvenlik denetimi yapın."),
    5432: _PortRisk(Severity.HIGH,     "PostgreSQL",  "PostgreSQL dışa açık.",                                           "PostgreSQL bağlantısını localhost ile sınırlayın."),
    5900: _PortRisk(Severity.HIGH,     "VNC",         "VNC servisi açık. Ekran paylaşımı yetkisiz erişime açık.",        "VNC'yi VPN arkasına alın veya SSH tüneli üzerinden kullanın."),
    6379: _PortRisk(Severity.CRITICAL, "Redis",       "Redis kimlik doğrulaması olmadan dışa açık.",                     "Redis'te requirepass ayarlayın, bind 127.0.0.1 ile bağlayın."),
    8080: _PortRisk(Severity.LOW,      "HTTP-Alt",    "Alternatif HTTP portu açık.",                                     "Gereksizse kapatın, HTTPS'e yönlendirin."),
    8443: _PortRisk(Severity.LOW,      "HTTPS-Alt",   "Alternatif HTTPS portu açık.",                                    "Gerekli değilse kapatın."),
    27017:_PortRisk(Severity.CRITICAL, "MongoDB",     "MongoDB kimlik doğrulaması olmadan dışa açık.",                   "MongoDB auth aktif edin, internet erişimini engelleyin."),
}


# ── _NmapCore ──────────────────────────────────────────────────────────────────

class _NmapCore:
    """
    Düşük seviyeli Nmap tarama motoru.

    Bu sınıfı kendi vize proje implementasyonunuz ile değiştirebilirsiniz.
    Gerekli tek şey: open_ports() metodu açık portların listesini döndürmeli.

    Attributes:
        target  (str): Taranacak IP adresi veya hostname.
        ports   (str): Port aralığı (ör. "1-1024", "22,80,443").
        timeout (int): Nmap zaman aşımı (saniye).
    """

    def __init__(self, target: str, ports: str, timeout: int) -> None:
        self.target  = target
        self.ports   = ports
        self.timeout = timeout

    def open_ports(self) -> list[int]:
        """
        Hedef üzerindeki açık portları döndürür.

        nmap -sV -oX - komutu ile XML çıktısı parse edilir.
        nmap kurulu değilse boş liste döner (graceful degradation).

        Returns:
            list[int]: Açık port numaraları listesi.
        """
        try:
            cmd = [
                "nmap",
                "-sV",          # servis/versiyon tespiti
                "--open",        # sadece açık portlar
                "-p", self.ports,
                "--host-timeout", f"{self.timeout}s",
                "-oX", "-",      # XML çıktı (stdout)
                self.target,
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 30,
            )
            return self._parse_xml(proc.stdout)

        except FileNotFoundError:
            # Nmap kurulu değil — geliştirme ortamı için graceful degradation
            print("      ⚠️  Nmap bulunamadı. PATH kontrolü yapın veya 'brew install nmap'.")
            return []
        except subprocess.TimeoutExpired:
            print(f"      ⚠️  Nmap zaman aşımı: {self.target}")
            return []

    def _parse_xml(self, xml_output: str) -> list[int]:
        """
        Nmap XML çıktısını parse ederek açık port listesi üretir.

        Args:
            xml_output (str): Nmap'in -oX - çıktısı.

        Returns:
            list[int]: Açık portlar.
        """
        open_ports: list[int] = []
        if not xml_output.strip():
            return open_ports

        try:
            root = ET.fromstring(xml_output)
            for host in root.findall("host"):
                ports_elem = host.find("ports")
                if ports_elem is None:
                    continue
                for port in ports_elem.findall("port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        portid = port.get("portid")
                        if portid:
                            open_ports.append(int(portid))
        except ET.ParseError:
            pass

        return open_ports


# ── NmapScannerTool ────────────────────────────────────────────────────────────

class NmapScannerTool:
    """
    Vize projesi Nmap tarayıcısının VultronScanner adaptörü.

    Bu sınıf _NmapCore'u kullanarak port taraması yapar ve
    sonuçları Finding nesnelerine dönüştürür.

    Vize kodunuzu entegre etmek için:
        _NmapCore sınıfını kendi implementasyonunuz ile değiştirin.
        open_ports() metodunun list[int] döndürdüğünden emin olun.

    Attributes:
        target  (str): Taranacak hedef.
        ports   (str): Port aralığı.
        timeout (int): Zaman aşımı.
        _core (_NmapCore): Gerçek tarama motoru.

    Örnek:
        >>> scanner = NmapScannerTool("192.168.1.1", "1-1024")
        >>> findings = scanner.scan()
        >>> for f in findings:
        ...     print(f.severity.value, f.title)
    """

    MODULE_NAME = "ViseNmap"

    def __init__(
        self,
        target: str,
        ports: str = "1-1024",
        timeout: int = 10,
    ) -> None:
        self.target  = target
        self.ports   = ports
        self.timeout = timeout
        self._core   = _NmapCore(target, ports, timeout)

    def scan(self) -> list[Finding]:
        """
        Port taraması gerçekleştirir ve bulguları döndürür.

        Returns:
            list[Finding]: Tespit edilen açık portlara ait bulgular.
        """
        findings: list[Finding] = []
        open_ports = self._core.open_ports()

        for port in open_ports:
            risk = _HIGH_RISK_PORTS.get(port)
            if risk:
                finding = Finding(
                    title=f"Açık Risk Port: {port}/{risk.service}",
                    severity=risk.severity,
                    description=risk.description,
                    recommendation=risk.recommendation,
                    module=self.MODULE_NAME,
                    target=f"{self.target}:{port}",
                    evidence=f"Nmap taraması — port {port}/tcp açık ({risk.service})",
                )
            else:
                finding = Finding(
                    title=f"Açık Port Tespit Edildi: {port}/tcp",
                    severity=Severity.INFO,
                    description=f"Port {port}/tcp açık durumda. Servis henüz tanımlanmamış.",
                    recommendation="Gerekli değilse portu kapatın veya güvenlik duvarı kuralı ekleyin.",
                    module=self.MODULE_NAME,
                    target=f"{self.target}:{port}",
                    evidence=f"Nmap taraması — port {port}/tcp açık",
                )
            findings.append(finding)

        return findings
