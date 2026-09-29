import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from nmapshot import cli, targets
from tests.test_nmapshot import ROOT


class ScopeTests(unittest.TestCase):
    def test_exclusion_always_wins_and_nothing_is_in_scope_without_includes(self):
        scope = targets.Scope(["10.0.0.0/8", "2001:db8::/32"], ["10.0.5.0/24", "10.0.6.7/32"])
        cases = {"10.1.2.3": scope.IN, "10.0.5.9": scope.EXCLUDED, "10.0.6.7": scope.EXCLUDED,
                 "10.0.6.8": scope.IN, "192.168.1.1": scope.OUT, "2001:db8::1": scope.IN, "2001:db9::1": scope.OUT}
        for ip, expected in cases.items():
            with self.subTest(ip=ip):
                self.assertEqual(scope.status(ip), expected)
        self.assertEqual(targets.Scope([], []).status("10.1.2.3"), targets.Scope.OUT)
        self.assertEqual(targets.Scope([], ["10.1.2.3"]).status("10.1.2.3"), targets.Scope.EXCLUDED)

    def test_parse_scope_lines_normalizes_and_keeps_reasons(self):
        rules = targets.parse_scope_lines("﻿# cabecera\n172.31.253.241   # A10 producción\n10.0.0.1/8\n\n10.0.0.0/8 # repetida\n")
        self.assertEqual(rules, [("172.31.253.241/32", "A10 producción"), ("10.0.0.0/8", "")])
        with self.assertRaisesRegex(ValueError, "Línea 2"):
            targets.parse_scope_lines("10.0.0.0/8\n300.1.1.1\n")

    def test_console_applies_scope_just_before_capturing(self):
        with tempfile.TemporaryDirectory() as temporary:
            ranges, excluded = Path(temporary, "rangos.txt"), Path(temporary, "excluir.txt")
            ranges.write_text("10.10.0.0/17\n")
            excluded.write_text("10.10.6.20/32\n")
            output = io.StringIO()
            base = ["capturar", str(ROOT / "ejemplos/escaneo.xml"), "-r", str(ranges), "--simular"]
            with contextlib.redirect_stdout(output):
                cli.main(base)
                everything = output.getvalue()
                output.seek(0), output.truncate()
                cli.main(base + ["--solo-rangos", "--excluir", str(excluded)])
            self.assertIn("192.168.1.8", everything)
            self.assertIn("10.10.6.20", everything)
            limited = output.getvalue()
            self.assertIn("2 URLs en 1 subredes", limited)
            self.assertIn("2 IP fuera de alcance o excluidas", limited)
            self.assertNotIn("192.168.1.8", limited)
            self.assertNotIn("10.10.6.20/", limited)
