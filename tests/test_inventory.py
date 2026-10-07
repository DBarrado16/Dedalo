import csv
import io
import unittest

from dedalo import inventory, parser, targets
from tests.test_dedalo import ROOT


class InventoryTests(unittest.TestCase):
    def test_all_formats_keep_open_tcp_udp_but_capture_only_tcp(self):
        outputs = []
        for extension in ("xml", "gnmap", "nmap"):
            hosts = parser.parse_file(ROOT / "ejemplos" / f"escaneo.{extension}")
            data = inventory.build(hosts, ["10.10.0.0/17"])
            outputs.append([(a["ip"], [(s["puerto"], s["protocolo"]) for s in a["servicios"]]) for a in data["activos"]])
            self.assertEqual(data["activos_total"], 3)
            self.assertEqual(data["servicios_total"], 7)
            self.assertEqual(len(targets.select_targets(hosts, targets.DEFAULT_PORTS)), 4)
        self.assertEqual(outputs, [outputs[0]] * 3)

    def test_xml_preserves_versions_cpe_scripts_and_hosts_without_web(self):
        hosts = parser.parse_file(ROOT / "ejemplos/inventario.xml")
        data = inventory.build(hosts, ["192.0.2.0/24", "2001:db8::/48"])
        self.assertEqual((data["activos_total"], data["servicios_total"], data["subredes_total"]), (4, 9, 2))
        web, directory, no_ports, ipv6 = data["activos"]
        ssh = web["servicios"][0]
        self.assertEqual((ssh["producto"], ssh["version"], ssh["detalle"]), ("OpenSSH", "9.6", "Ubuntu Linux"))
        self.assertEqual(ssh["cpe"], ["cpe:/a:openbsd:openssh:9.6"])
        self.assertEqual(ssh["scripts"][0]["id"], "ssh-hostkey")
        self.assertEqual(directory["scripts"][0]["id"], "smb-os-discovery")
        self.assertEqual(directory["nombres"], ["directorio.ejemplo.test"])
        self.assertEqual(sum(s["puerto"] == 53 for s in directory["servicios"]), 2)
        self.assertEqual(no_ports["servicios"], [])
        self.assertEqual(ipv6["subred"], "2001:db8::/64")
        self.assertEqual(len(targets.select_targets(hosts, targets.DEFAULT_PORTS)), 2)

    def test_merge_deduplicates_protocols_without_mixing_executions(self):
        hosts = parser.parse_file(ROOT / "ejemplos/inventario.xml")
        data = inventory.build(parser.merge([hosts, hosts]), [])
        self.assertEqual(data["servicios_total"], 9)
        self.assertEqual(len(data["activos"][1]["scripts"]), 1)
        self.assertEqual(data["activos"][0]["rango"], "fuera_de_rango")

    def test_normal_format_ignores_reason_column(self):
        text = ("Nmap scan report for 192.0.2.1\nHost is up, received user-set (0.016s latency).\n"
                "PORT   STATE SERVICE REASON\n22/tcp open  ssh     syn-ack ttl 251\n"
                "Nmap scan report for 192.0.2.2\n"
                "PORT    STATE SERVICE  REASON          VERSION\n443/tcp open  ssl/http syn-ack ttl 64 nginx 1.24\n"
                "53/udp  open  domain   udp-response ttl 64 dnsmasq 2.90\n"
                "Nmap scan report for 192.0.2.3\n"
                "PORT   STATE SERVICE VERSION\n80/tcp open  http    Apache httpd 2.4\n")
        first, second, third = parser.parse_text(text)
        self.assertEqual(first.ports[22].product, "")
        self.assertEqual((second.ports[443].tunnel, second.ports[443].product), ("ssl", "nginx 1.24"))
        self.assertEqual(second.udp_ports[53].product, "dnsmasq 2.90")
        self.assertEqual(third.ports[80].product, "Apache httpd 2.4")

    def test_csv_keeps_hosts_without_ports_and_neutralizes_formulas(self):
        hosts = [parser.Host("192.0.2.1", hostnames=["=test"]),
                 parser.Host("192.0.2.2", ports={22: parser.Port(22, product="@product", version="1")})]
        data = inventory.build(hosts, [])
        result = list(csv.DictReader(io.StringIO(inventory.csv_bytes(data).decode("utf-8-sig"))))
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["puerto"], "")
        self.assertEqual(result[0]["nombres"], "'=test")
        self.assertEqual(result[1]["producto"], "'@product")
        self.assertEqual(result[1]["version"], "1")
