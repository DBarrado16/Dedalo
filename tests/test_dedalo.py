from contextlib import redirect_stdout, redirect_stderr
import csv
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from dedalo import cli, gowitness, parser, report, targets, views

ROOT = Path(__file__).resolve().parent.parent


def fake_database(directory, urls, missing_file=False):
    directory = Path(directory)
    (directory / "capturas").mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(directory / gowitness.DB_NAME)
    con.execute("CREATE TABLE results (id INTEGER PRIMARY KEY, url TEXT, final_url TEXT, response_code INTEGER, title TEXT, filename TEXT, failed INTEGER)")
    for i, url in enumerate(urls):
        filename = f"shot-{i}.png"
        if not missing_file:
            (directory / "capturas" / filename).write_bytes(b"test-image")
        con.execute("INSERT INTO results VALUES (?, ?, ?, 200, ?, ?, 0)", (i, url, url, "=test", filename))
    con.commit()
    con.close()


class ParserTests(unittest.TestCase):
    def test_formats_produce_same_targets(self):
        outputs = []
        for extension in ("xml", "gnmap", "nmap"):
            hosts = parser.parse_file(ROOT / "ejemplos" / f"escaneo.{extension}")
            result = targets.select_targets(hosts, targets.DEFAULT_PORTS)
            outputs.append(sorted(t.url for t in result))
        self.assertEqual(outputs, [outputs[0]] * 3)
        self.assertEqual(outputs[0], [
            "http://10.10.5.10/", "http://10.10.6.20/",
            "https://10.10.5.10/", "https://192.168.1.8/",
        ])

    def test_merge_deduplicates(self):
        hosts = parser.merge([parser.parse_file(ROOT / "ejemplos" / f"escaneo.{e}") for e in ("xml", "gnmap", "nmap")])
        self.assertEqual(len(targets.select_targets(hosts, targets.DEFAULT_PORTS)), 4)

    def test_service_detection_and_extra_ports(self):
        hosts = parser.parse_file(ROOT / "ejemplos/escaneo.xml")
        extras = {**targets.DEFAULT_PORTS, **targets.parse_port_map("8443=https")}
        self.assertEqual(len(targets.select_targets(hosts, extras)), 5)
        results = targets.select_targets(hosts, targets.DEFAULT_PORTS, by_service=True)
        self.assertIn("https://10.10.6.20:8443/", [t.url for t in results])

    def test_invalid_and_empty_input(self):
        for text in ("", "cualquier texto", '<?xml version="1.0"?><otro/>'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parser.parse_text(text)
        self.assertEqual(parser.parse_text("<nmaprun/>"), [])
        self.assertEqual(parser.parse_text("# Nmap done: 0 hosts up"), [])

    def test_bom_and_ipv6(self):
        hosts = parser.parse_text('\ufeff<nmaprun><host><status state="up"/><address addr="2001:0db8::1" addrtype="ipv6"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host></nmaprun>')
        self.assertEqual(targets.select_targets(hosts, targets.DEFAULT_PORTS)[0].url, "https://[2001:db8::1]/")

    def test_invalid_ports(self):
        for value in ("0=http", "65536=https", "abc=http", "80=ftp", "8080"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                targets.parse_port_map(value)

    def test_only_exact_open_tcp(self):
        hosts = parser.parse_text("Nmap scan report for 10.0.0.1\n80/tcp open|filtered http\n443/udp open https\n")
        self.assertFalse(targets.select_targets(hosts, targets.DEFAULT_PORTS))


class NetworkTests(unittest.TestCase):
    def test_ranges(self):
        resolver = targets.SubnetResolver(["10.10.0.0/17", "10.10.4.0/22", "10.10.5.0/26"])
        self.assertEqual(tuple(map(str, resolver.resolve("10.10.9.10"))), ("10.10.0.0/17", "10.10.9.0/24"))
        self.assertEqual(tuple(map(str, resolver.resolve("10.10.6.10"))), ("10.10.4.0/22", "10.10.6.0/24"))
        self.assertEqual(tuple(map(str, resolver.resolve("10.10.5.10"))), ("10.10.5.0/26", "10.10.5.0/26"))
        self.assertEqual(tuple(map(str, resolver.resolve("192.168.1.10"))), ("fuera_de_rango", "192.168.1.0/24"))

    def test_ipv6_and_windows_folder(self):
        resolver = targets.SubnetResolver(["2001:db8::/48"])
        self.assertEqual(tuple(map(str, resolver.resolve("2001:db8:0:1::5"))), ("2001:db8::/48", "2001:db8:0:1::/64"))
        self.assertNotIn(":", cli.folder_name("2001:db8::/64"))

    def test_view_selection_and_path_escape(self):
        manifest = {"grupos": [{"rango": "10.10.0.0/17", "subred": "10.10.5.0/24"},
                              {"rango": "10.10.0.0/17", "subred": "10.10.6.0/24"}]}
        self.assertEqual(len(views.select_groups(manifest, "10.10.0.0/17")), 2)
        self.assertEqual(len(views.select_groups(manifest, "10.10.5.0/24")), 1)
        with self.assertRaises(ValueError):
            views.select_groups(manifest, "172.16.0.0/16")
        with self.assertRaises(ValueError):
            report.inside(ROOT, "../outside")
        with self.assertRaises(ValueError):
            gowitness.screenshot_path(ROOT, "../../outside.png")


class WorkflowTests(unittest.TestCase):
    def call(self, arguments):
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            code = cli.main(arguments)
        return code, output.getvalue()

    def arguments(self, destination):
        return ["capturar", str(ROOT / "ejemplos/escaneo.xml"),
                "-r", str(ROOT / "ejemplos/rangos.txt"), "-o", str(destination)]

    def test_dry_run_has_no_files_or_gowitness(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "salida"
            with patch("dedalo.gowitness.find_gowitness", side_effect=AssertionError("No ejecutar")):
                code, output = self.call(self.arguments(destination) + ["--simular"])
            self.assertEqual(code, 0)
            self.assertIn("4 URLs en 3 subredes", output)
            self.assertFalse(destination.exists())

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            marker = destination / "keep.txt"
            marker.write_text("original")
            with patch("dedalo.gowitness.find_gowitness", return_value="fake"), patch("dedalo.gowitness.find_chrome", return_value="fake"):
                code, output = self.call(self.arguments(destination))
            self.assertEqual(code, 1)
            self.assertIn("no está vacía", output)
            self.assertEqual(marker.read_text(), "original")
            self.assertFalse((destination / report.MANIFEST).exists())

    def test_partial_capture_and_index(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "salida"
            def scan(binary, directory, urls, opts):
                (Path(directory) / "urls.txt").write_text("\n".join(urls))
                fake_database(directory, urls[:1])
            with patch("dedalo.gowitness.find_gowitness", return_value="fake"), patch("dedalo.gowitness.find_chrome", return_value="fake"), patch("dedalo.gowitness.scan_subnet", side_effect=scan):
                code, output = self.call(self.arguments(destination))
            self.assertEqual(code, 3, output)
            data = report.load_manifest(destination)
            self.assertEqual(data["estado"], "parcial")
            self.assertEqual(sum(g["capturas"] for g in data["grupos"]), 3)
            with (destination / "indice.csv").open(encoding="utf-8-sig", newline="") as file:
                rows = list(csv.DictReader(file))
            self.assertEqual(len(rows), 4)
            self.assertEqual(sum(r["estado"] == "sin_captura" for r in rows), 1)
            self.assertTrue(all(r["titulo"] == "'=test" for r in rows if r["captura"]))
            missing = destination / "10.10.0.0_17/10.10.5.0_24/sin_captura.txt"
            self.assertEqual(missing.read_text().strip(), "https://10.10.5.10/")
            code, output = self.call(["ver", str(destination), "--listar"])
            self.assertEqual(code, 0)
            self.assertIn("10.10.5.0/24", output)

    def fake_engine(self, calls, retry_works=True):
        """gowitness simulado: en la primera pasada las HTTPS cargan pero se quedan sin imagen."""
        def scan(binary, directory, urls, opts, urls_file=gowitness.URLS_FILE, log_name=gowitness.LOG_NAME):
            directory = Path(directory)
            calls.append((opts["driver"], log_name, list(urls)))
            (directory / "capturas").mkdir(parents=True, exist_ok=True)
            con = sqlite3.connect(directory / gowitness.DB_NAME)
            con.execute("CREATE TABLE IF NOT EXISTS results (id INTEGER PRIMARY KEY, url TEXT, final_url TEXT, "
                        "response_code INTEGER, title TEXT, filename TEXT, failed INTEGER)")
            errors = []
            for url in urls:
                exact = gowitness.explicit_port(url)
                if url.startswith("https://") and (log_name == gowitness.LOG_NAME or not retry_works):
                    con.execute("INSERT INTO results (url, final_url, response_code, title, filename, failed) "
                                "VALUES (?, ?, 200, 'Sin imagen', '', 0)", (exact, url))
                    errors.append(f'ERRO could not grab screenshot target={exact} err="context deadline exceeded"')
                else:
                    name = f"{len(calls)}-{url.split('//')[1].strip('/').replace(':', '_')}.png"
                    (directory / "capturas" / name).write_bytes(b"test-image")
                    con.execute("INSERT INTO results (url, final_url, response_code, title, filename, failed) "
                                "VALUES (?, ?, 200, 'Con imagen', ?, 0)", (exact, url, name))
            con.commit()
            con.close()
            (directory / log_name).write_text("".join(line + "\n" for line in errors), encoding="utf-8")
        return scan

    def run_with(self, destination, scan, extra=()):
        with patch("dedalo.gowitness.find_gowitness", return_value="fake"), \
                patch("dedalo.gowitness.find_chrome", return_value="fake"), \
                patch("dedalo.gowitness.scan_subnet", side_effect=scan):
            return self.call(self.arguments(destination) + list(extra))

    def test_pages_without_image_are_retried_with_the_other_engine(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination, calls = Path(temporary) / "salida", []
            code, output = self.run_with(destination, self.fake_engine(calls))
            self.assertEqual(code, 0, output)
            self.assertEqual([c for c in calls if c[1] == gowitness.RETRY_LOG], [
                ("chromedp", gowitness.RETRY_LOG, ["https://10.10.5.10/"]),
                ("chromedp", gowitness.RETRY_LOG, ["https://192.168.1.8/"]),
            ])
            self.assertTrue(all(c[0] == "gorod" for c in calls if c[1] == gowitness.LOG_NAME))
            data = report.load_manifest(destination)
            self.assertEqual((data["estado"], data["opciones"]["driver"], data["opciones"]["retry"]), ("completa", "gorod", True))
            titles = {r["url"]: r["titulo"] for g in data["grupos"] for r in g["resultados"]}
            self.assertEqual(titles["https://10.10.5.10/"], "Con imagen")
            self.assertIn("se reintentan con el motor chromedp", output)

    def test_retry_can_be_disabled_and_reports_when_it_also_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            calls = []
            code, _ = self.run_with(Path(temporary) / "sin", self.fake_engine(calls), ["--sin-reintento", "--driver", "chromedp"])
            self.assertEqual(code, 3)
            self.assertEqual({c[:2] for c in calls}, {("chromedp", gowitness.LOG_NAME)})
            calls = []
            destination = Path(temporary) / "falla"
            code, _ = self.run_with(destination, self.fake_engine(calls, retry_works=False))
            self.assertEqual(code, 3)
            rows = {r["url"]: r for g in report.load_manifest(destination)["grupos"] for r in g["resultados"]}
            self.assertEqual(rows["https://10.10.5.10/"]["estado"], "sin_captura")
            self.assertEqual(rows["https://10.10.5.10/"]["error"],
                             "También sin imagen al reintentar con el otro motor: context deadline exceeded")

    def test_connection_errors_are_not_retried(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / gowitness.LOG_NAME).write_text(
                'ERRO failed to witness target target=http://10.0.0.1:80/ err="page load error net::ERR_CONNECTION_REFUSED"\n'
                'ERRO could not grab screenshot target=http://10.0.0.2:80/ err="context deadline exceeded"\n', encoding="utf-8")
            self.assertEqual(gowitness.retry_candidates(directory, ["http://10.0.0.1/", "http://10.0.0.2/", "http://10.0.0.3/"]),
                             ["http://10.0.0.2/"])

    def test_failed_binary_continues_other_groups(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "salida"
            with patch("dedalo.gowitness.find_gowitness", return_value="fake"), patch("dedalo.gowitness.find_chrome", return_value="fake"), patch("dedalo.gowitness.scan_subnet", side_effect=subprocess.CalledProcessError(1, ["fake"])) as scanner:
                code, _ = self.call(self.arguments(destination))
            self.assertEqual(code, 1)
            self.assertEqual(scanner.call_count, 3)
            data = report.load_manifest(destination)
            self.assertTrue(all(g["estado"] == "error" for g in data["grupos"]))

    def test_interruption_keeps_pending_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "salida"
            with patch("dedalo.gowitness.find_gowitness", return_value="fake"), patch("dedalo.gowitness.find_chrome", return_value="fake"), patch("dedalo.gowitness.scan_subnet", side_effect=KeyboardInterrupt):
                code, _ = self.call(self.arguments(destination))
            self.assertEqual(code, 130)
            data = report.load_manifest(destination)
            self.assertEqual(data["estado"], "interrumpida")
            self.assertEqual(data["grupos"][1]["estado"], "pendiente")

    def test_missing_screenshot_and_corrupt_database(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fake_database(directory, ["http://127.0.0.1:80"], missing_file=True)
            self.assertEqual(gowitness.read_results(directory / gowitness.DB_NAME), {})
            (directory / "capturas/shot-0.png").write_bytes(b"test")
            self.assertIn("http://127.0.0.1/", gowitness.read_results(directory / gowitness.DB_NAME))
            with self.assertRaises(ValueError):
                gowitness.normalize_url("http://127.0.0.1:bad/")
            (directory / gowitness.DB_NAME).write_bytes(b"not a database")
            with self.assertRaises(sqlite3.DatabaseError):
                gowitness.read_results(directory / gowitness.DB_NAME)

    def test_explicit_executable_is_absolute(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fake-gowitness"
            path.touch()
            executable = gowitness.find_gowitness(str(path))
            self.assertTrue(Path(executable).is_absolute())

    def test_capture_errors_are_associated_with_exact_url(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.assertEqual(gowitness.read_errors(directory), {})
            (directory / "gowitness.log").write_text(
                'ERRO failed to witness target target=http://10.0.0.1:80/ err="page load error net::ERR_NETWORK_ACCESS_DENIED"\n'
                'ERRO failed to witness target target=https://10.0.0.1:443/ err="page load error net::ERR_CONNECTION_REFUSED"\n'
                'ERRO could not grab screenshot target=http://10.0.0.2:80/ err="context deadline exceeded"\n'
                'ERRO failed to witness target target=http://10.0.0.3:80/ err="page load error net::ERR_INVALID_AUTH_CREDENTIALS"\n'
                'unrelated startup message\n', encoding="utf-8")
            group = {"rango": "fuera_de_rango", "subred": "10.0.0.0/24", "carpeta": "subnet",
                     "objetivos": [{"ip": "10.0.0.1", "port": 80, "url": "http://10.0.0.1/"},
                                   {"ip": "10.0.0.1", "port": 443, "url": "https://10.0.0.1/"}]}
            errors = gowitness.read_errors(directory)
            self.assertIn("ERR_NETWORK_ACCESS_DENIED", errors["http://10.0.0.1/"])
            self.assertIn("ERR_CONNECTION_REFUSED", errors["https://10.0.0.1/"])
            self.assertEqual("context deadline exceeded", errors["http://10.0.0.2/"])
            self.assertIn("autenticación HTTP", errors["http://10.0.0.3/"])
            subnet = directory / "subnet"
            subnet.mkdir()
            (directory / "gowitness.log").rename(subnet / "gowitness.log")
            report.collect_group(directory, group)
            self.assertIn("ERR_NETWORK_ACCESS_DENIED", group["resultados"][0]["error"])
            self.assertIn("ERR_CONNECTION_REFUSED", group["resultados"][1]["error"])

    def test_explicit_ports_prevent_gowitness_expansion(self):
        self.assertEqual(gowitness.explicit_port("http://10.0.0.1/"), "http://10.0.0.1:80/")
        self.assertEqual(gowitness.explicit_port("https://[2001:db8::1]/"), "https://[2001:db8::1]:443/")
        self.assertEqual(gowitness.explicit_port("http://10.0.0.1:8080/"), "http://10.0.0.1:8080/")

    @unittest.skipUnless(os.name == "nt", "Compatibilidad específica de Edge en Windows")
    def test_existing_headless_chromium_is_preferred_to_edge(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            edge = root / "Microsoft/Edge/Application/msedge.exe"
            edge.parent.mkdir(parents=True)
            edge.touch()
            shells = []
            for version in (999, 1234):
                shell = root / f"ms-playwright/chromium_headless_shell-{version}/chrome-headless-shell-win64/chrome-headless-shell.exe"
                shell.parent.mkdir(parents=True)
                shell.touch()
                shells.append(shell)
            with patch.dict(os.environ, {"LOCALAPPDATA": temporary, "ProgramFiles": temporary, "ProgramFiles(x86)": temporary}):
                self.assertEqual(gowitness.find_chrome(None), str(shells[-1].resolve()))
                self.assertEqual(gowitness.find_chrome(str(edge)), str(edge.resolve()))
                for shell in shells:
                    shell.unlink()
                self.assertEqual(gowitness.find_chrome(None), str(edge.resolve()))

    @unittest.skipUnless(os.name == "nt", "Compatibilidad específica de Edge en Windows")
    def test_edge_does_not_inherit_compatibility_layer(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.dict(os.environ, {"__COMPAT_LAYER": "DetectorsAppHealth"}):
                with patch("dedalo.gowitness.subprocess.run") as run:
                    gowitness.scan_subnet("fake", temporary, ["http://127.0.0.1/"], {
                        "threads": 1, "timeout": 5, "delay": 0, "format": "png", "chrome": "msedge.exe",
                    })
                self.assertNotIn("__COMPAT_LAYER", run.call_args.kwargs["env"])
                command = run.call_args.args[0]
                self.assertEqual(command[command.index("--driver") + 1], "gorod")
                self.assertEqual(os.environ["__COMPAT_LAYER"], "DetectorsAppHealth")
                self.assertEqual((Path(temporary) / "urls.txt").read_text().strip(), "http://127.0.0.1:80/")


if __name__ == "__main__":
    unittest.main()


class ManifestWriteTests(unittest.TestCase):
    def test_manifest_is_replaced_while_the_portal_is_reading_it(self):
        # En Windows, sustituir un archivo abierto por otro falla; el motor no debe caer por ello.
        import threading
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report.save_manifest(root, {"version": 1, "grupos": [], "estado": "en_curso"})
            reader = (root / report.MANIFEST).open(encoding="utf-8")
            timer = threading.Timer(0.3, reader.close)
            timer.start()
            try:
                report.save_manifest(root, {"version": 1, "grupos": [], "estado": "completa"})
            finally:
                timer.join()
                reader.close()
            self.assertEqual(report.load_manifest(root)["estado"], "completa")

    def test_folder_resolved_with_long_path_prefix_is_still_inside(self):
        # Windows puede resolver con \\?\ una carpeta que se está creando en ese momento.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = Path.resolve
            prefixed = lambda self, strict=False: Path("\\\\?\\" + str(real(self))) if self.name == "b_24" else real(self)
            with patch.object(Path, "resolve", prefixed):
                self.assertEqual(report.inside(root, "a_17/b_24"), real(root) / "a_17" / "b_24")
                for evil in ("../b_24", "\\\\?\\C:\\b_24"):
                    with self.subTest(evil=evil), self.assertRaises(ValueError):
                        report.inside(root, evil)

    def test_replace_gives_up_if_the_file_stays_locked(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch("dedalo.report.os.replace", side_effect=PermissionError("ocupado")) as replace, \
                patch("dedalo.report.time.sleep"):
            with self.assertRaises(PermissionError):
                report.replace(Path(temporary) / "a", Path(temporary) / "b", attempts=3)
        self.assertEqual(replace.call_count, 3 if os.name == "nt" else 1)
