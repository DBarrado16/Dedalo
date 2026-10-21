import csv
import io
from pathlib import Path
import tempfile
import unittest

from dedalo import inventory, parser, report, targets, vulnerabilidades
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


def vuln(cve, severidad, nivel="ninguno", enlaces=()):
    return {"cve": cve, "severidad": severidad, "exploit_nivel": nivel, "enlaces_exploit": list(enlaces),
            "cpe": "cpe:/a:openbsd:openssh:9.6", "fuente_cpe": "nmap"}


class VulnerabilitiesInTheInventoryTests(unittest.TestCase):
    """Lo que dejó el cruce por CPE llega al CSV y al JSON, y «sin datos» no se lee como «limpio»."""

    EXPLOIT = "https://www.exploit-db.com/exploits/12345"
    RESULTADOS = [
        {"ip": "192.0.2.2", "protocolo": "tcp", "puerto": 22, "estado": "ok",
         "vulns": [vuln("CVE-2026-0002", "HIGH"), vuln("CVE-2026-0001", "CRITICAL", "confirmado", [EXPLOIT])]},
        {"ip": "192.0.2.2", "protocolo": "tcp", "puerto": 80, "estado": "ok", "vulns": []},
        {"ip": "192.0.2.2", "protocolo": "tcp", "puerto": 443, "estado": "sin_datos", "vulns": []},
        {"ip": "192.0.2.9", "protocolo": "tcp", "puerto": 22, "estado": "ok", "vulns": [vuln("CVE-2026-0003", "LOW")]},
    ]

    def data(self):
        hosts = [parser.Host("192.0.2.1"),
                 parser.Host("192.0.2.2", ports={p: parser.Port(p) for p in (22, 80, 443, 8080)})]
        data = inventory.build(hosts, [])
        inventory.add_vulns(data, self.RESULTADOS)
        return data

    def rows(self):
        text = inventory.csv_bytes(self.data()).decode("utf-8-sig")
        return {(r["ip"], r["puerto"]): r for r in csv.DictReader(io.StringIO(text))}

    def test_the_csv_lists_cve_severity_exploit_level_and_links_worst_first(self):
        row = self.rows()[("192.0.2.2", "22")]
        self.assertEqual(row["vuln_estado"], "con_vulnerabilidades")
        self.assertEqual(row["vuln_cves"], "CVE-2026-0001; CVE-2026-0002")
        self.assertEqual(row["vuln_severidades"], "CRITICAL; HIGH")
        self.assertEqual(row["vuln_exploits"], "confirmado; ninguno")
        self.assertEqual(row["vuln_enlaces"], self.EXPLOIT)
        self.assertEqual(row["vuln_prioridad"], "0")

    def test_no_data_is_told_apart_from_no_vulnerabilities_and_from_not_crossed(self):
        rows = self.rows()
        limpio, sin_datos, sin_cruzar = rows[("192.0.2.2", "80")], rows[("192.0.2.2", "443")], rows[("192.0.2.2", "8080")]
        self.assertEqual((limpio["vuln_estado"], limpio["vuln_prioridad"]), ("sin_vulnerabilidades", "4"))
        self.assertEqual((sin_datos["vuln_estado"], sin_datos["vuln_prioridad"]), ("sin_datos", ""))
        self.assertEqual((sin_cruzar["vuln_estado"], sin_cruzar["vuln_prioridad"]), ("", ""))
        for row in (limpio, sin_datos, sin_cruzar):
            self.assertEqual((row["vuln_cves"], row["vuln_severidades"], row["vuln_exploits"], row["vuln_enlaces"]), ("", "", "", ""))

    def test_a_host_without_ports_and_a_result_for_another_ip_leave_the_columns_empty(self):
        row = self.rows()[("192.0.2.1", "")]
        self.assertEqual({row[c] for c in ("vuln_estado", "vuln_prioridad", "vuln_cves")}, {""})
        self.assertNotIn("CVE-2026-0003", inventory.csv_bytes(self.data()).decode("utf-8-sig"))  # 192.0.2.9 no está

    def test_the_json_keeps_the_vulnerabilities_ordered_and_marks_every_service(self):
        ssh, web, sin_datos, sin_cruzar = self.data()["activos"][1]["servicios"]
        self.assertEqual([v["cve"] for v in ssh["vulnerabilidades"]], ["CVE-2026-0001", "CVE-2026-0002"])
        self.assertEqual(ssh["vulnerabilidades"][0]["enlace"], "https://nvd.nist.gov/vuln/detail/CVE-2026-0001")
        self.assertEqual((ssh["vuln_estado"], ssh["vuln_prioridad"]), ("con_vulnerabilidades", 0))
        self.assertEqual((web["vuln_estado"], web["vulnerabilidades"]), ("sin_vulnerabilidades", []))
        self.assertEqual((sin_datos["vuln_estado"], sin_datos["vuln_prioridad"]), ("sin_datos", None))
        self.assertEqual((sin_cruzar["vuln_estado"], sin_cruzar["vulnerabilidades"]), ("", []))

    def test_an_exported_link_cannot_become_a_spreadsheet_formula(self):
        resultados = [{"ip": "192.0.2.2", "protocolo": "tcp", "puerto": 22, "estado": "ok",
                       "vulns": [vuln("CVE-2026-0001", "HIGH", "sin_verificar", ["=HYPERLINK(1)"])]}]
        data = inventory.build([parser.Host("192.0.2.2", ports={22: parser.Port(22)})], [])
        inventory.add_vulns(data, resultados)
        row = list(csv.DictReader(io.StringIO(inventory.csv_bytes(data).decode("utf-8-sig"))))[0]
        self.assertEqual(row["vuln_enlaces"], "'=HYPERLINK(1)")

    def test_an_inventory_never_crossed_exports_the_same_columns_empty(self):
        data = inventory.build([parser.Host("192.0.2.2", ports={22: parser.Port(22)})], [])
        row = list(csv.DictReader(io.StringIO(inventory.csv_bytes(data).decode("utf-8-sig"))))[0]
        self.assertEqual({row[c] for c in ("vuln_estado", "vuln_prioridad", "vuln_cves", "vuln_enlaces")}, {""})


class VulnerabilitiesInTheCaptureIndexTests(unittest.TestCase):
    """El índice de capturas (indice.csv) cuenta lo mismo que el inventario, por IP y puerto TCP."""

    def manifest(self):
        objetivos = [{"ip": ip, "port": port, "url": f"http://{ip}:{port}/"} for ip, port in
                     (("192.0.2.2", 80), ("192.0.2.2", 443), ("192.0.2.3", 80), ("192.0.2.4", 80))]
        return {"version": 1, "grupos": [{"rango": "r", "subred": "192.0.2.0/24", "objetivos": objetivos}]}

    def index(self, resultados):
        columnas = vulnerabilidades.columnas_tcp(resultados)
        return {(r["ip"], r["puerto"]): r for r in csv.DictReader(io.StringIO(report.index_bytes(self.manifest(), columnas).decode("utf-8-sig")))}

    def test_the_columns_are_the_ones_the_inventory_exports(self):
        self.assertEqual(report.COLUMNS[-6:], vulnerabilidades.COLUMNAS_EXPORTACION)

    def test_each_target_shows_its_vulnerabilities_and_no_data_is_not_clean(self):
        filas = self.index([
            {"ip": "192.0.2.2", "protocolo": "tcp", "puerto": 80, "estado": "ok",
             "vulns": [vuln("CVE-2026-0002", "HIGH"), vuln("CVE-2026-0001", "CRITICAL", "confirmado", ["https://www.exploit-db.com/exploits/1"])]},
            {"ip": "192.0.2.2", "protocolo": "tcp", "puerto": 443, "estado": "ok", "vulns": []},
            {"ip": "192.0.2.3", "protocolo": "tcp", "puerto": 80, "estado": "sin_datos", "vulns": []},
            {"ip": "192.0.2.4", "protocolo": "udp", "puerto": 80, "estado": "ok", "vulns": [vuln("CVE-2026-0009", "LOW")]},
        ])
        web = filas[("192.0.2.2", "80")]
        self.assertEqual((web["vuln_estado"], web["vuln_cves"], web["vuln_severidades"], web["vuln_exploits"], web["vuln_prioridad"]),
                         ("con_vulnerabilidades", "CVE-2026-0001; CVE-2026-0002", "CRITICAL; HIGH", "confirmado; ninguno", "0"))
        self.assertEqual(web["vuln_enlaces"], "https://www.exploit-db.com/exploits/1")
        self.assertEqual(filas[("192.0.2.2", "443")]["vuln_estado"], "sin_vulnerabilidades")
        self.assertEqual(filas[("192.0.2.3", "80")]["vuln_estado"], "sin_datos")
        # Un resultado UDP no es el del objetivo web TCP del mismo número: ese sigue sin cruzar.
        self.assertEqual((filas[("192.0.2.4", "80")]["vuln_estado"], filas[("192.0.2.4", "80")]["vuln_cves"]), ("", ""))

    def test_without_a_crossing_the_columns_are_empty_and_write_index_keeps_working(self):
        filas = self.index([])
        self.assertEqual({r["vuln_estado"] for r in filas.values()}, {""})
        with tempfile.TemporaryDirectory() as folder:
            report.write_index(Path(folder), self.manifest())
            texto = (Path(folder) / "indice.csv").read_text(encoding="utf-8-sig")
        self.assertEqual(list(csv.DictReader(io.StringIO(texto)))[0]["estado"], "pendiente")
        self.assertEqual(texto.splitlines()[0].split(",")[-6:], vulnerabilidades.COLUMNAS_EXPORTACION)
