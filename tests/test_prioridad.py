import json
import re
import unittest

from dedalo import inventory, parser, prioridad
from tests.test_dedalo import ROOT


def service(port, name, product=""):
    return {"puerto": port, "protocolo": "tcp", "servicio": name, "producto": product, "version": "", "detalle": ""}


DC = {"ip": "10.0.0.1", "nombres": ["dc01"], "servicios": [service(88, "kerberos"), service(389, "ldap"),
                                                          service(445, "microsoft-ds")]}
FILES = {"ip": "10.0.0.2", "nombres": [], "servicios": [service(445, "microsoft-ds"), service(2049, "nfs")]}
WEB = {"ip": "10.0.0.3", "nombres": [], "servicios": [service(443, "https")]}
DESK = {"ip": "10.0.0.9", "nombres": [], "servicios": [service(3389, "ms-wbt-server")]}


def answer(level, role="Rol"):
    return json.dumps({"rol": role, "nivel": level, "motivo": "Por sus servicios.", "siguiente": "Revisar primero."})


def by_ip(levels):
    """Modelo falso: responde a cada host con el nivel indicado para su IP."""
    def generate(prompt):
        ip = re.search(r'"ip": "([^"]+)"', prompt).group(1)
        return levels[ip]
    return generate


class PromptTests(unittest.TestCase):
    def test_the_host_goes_as_a_json_data_block(self):
        host = {"ip": "10.0.0.5", "nombres": [], "servicios": [service(80, "http", 'Panel "admin" {v2}')]}
        text = prioridad.build_prompt(host)
        block = re.search(r"```json\n(.*)\n```", text, re.DOTALL).group(1)
        self.assertEqual(json.loads(block), {"ip": "10.0.0.5", "nombres": [], "servicios": host["servicios"]})

    def test_only_metadata_reaches_the_model(self):
        host = dict(DC, scripts=[{"id": "x", "output": "volcado"}], alcance="en_alcance")
        host["servicios"] = [dict(DC["servicios"][0], scripts=[{"id": "y", "output": "otro volcado"}], cpe=["cpe:/a"])]
        text = prioridad.build_prompt(host)
        self.assertIn("kerberos", text)
        self.assertNotIn("volcado", text)
        self.assertNotIn("cpe:/a", text)


class ParseTests(unittest.TestCase):
    def test_accepts_the_object_even_inside_prose_or_fences(self):
        for text in (answer("alta", "DC"), "Aquí va:\n```json\n" + answer("alta", "DC") + "\n```"):
            with self.subTest(text=text):
                self.assertEqual(prioridad.parse_result(text),
                                 {"rol": "DC", "nivel": "alta", "motivo": "Por sus servicios.", "siguiente": "Revisar primero."})

    def test_rejects_what_does_not_fit_the_schema(self):
        for text in ("sin json", "{roto", "[1, 2]", answer("urgente"), '{"rol": "x"}'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                prioridad.parse_result(text)


class AnalysisTests(unittest.TestCase):
    def test_orders_by_level_then_by_number_of_services_then_ip(self):
        rows = prioridad.analizar([DESK, WEB, FILES, DC], by_ip({
            "10.0.0.1": answer("alta"), "10.0.0.2": answer("media"),
            "10.0.0.3": answer("media"), "10.0.0.9": answer("baja")}))
        self.assertEqual([(r["ip"], r["nivel"], r["orden"]) for r in rows],
                         [("10.0.0.1", "alta", 0), ("10.0.0.2", "media", 1), ("10.0.0.3", "media", 2), ("10.0.0.9", "baja", 3)])
        self.assertEqual(set(rows[0]), {"ip", "rol", "nivel", "motivo", "siguiente", "orden"})

    def test_a_host_with_an_unusable_answer_is_kept_last_without_analysis(self):
        rows = prioridad.analizar([DC, DESK], by_ip({"10.0.0.1": "no sé", "10.0.0.9": answer("baja")}))
        self.assertEqual([r["ip"] for r in rows], ["10.0.0.9", "10.0.0.1"])
        self.assertEqual(rows[1]["nivel"], "sin_analisis")
        self.assertTrue(rows[1]["motivo"])

    def test_if_the_model_cannot_answer_the_whole_analysis_fails(self):
        def unavailable(prompt):
            raise ValueError("No se pudo usar el modelo")
        with self.assertRaisesRegex(ValueError, "modelo"):
            prioridad.analizar([DC], unavailable)

    def test_the_lab_fixture_has_the_demo_hosts_in_the_demo_order(self):
        hosts = parser.merge([parser.parse_file(ROOT / "ejemplos" / "laboratorio.xml")])
        assets = inventory.build(hosts, ["10.30.0.0/16"])["activos"]
        self.assertEqual({a["ip"]: sorted(s["puerto"] for s in a["servicios"]) for a in assets},
                         {"10.30.1.10": [88, 389, 445], "10.30.1.21": [8443], "10.30.2.20": [445, 2049], "10.30.2.44": [3389]})
        rows = prioridad.analizar(assets, by_ip({"10.30.1.10": answer("alta"), "10.30.1.21": answer("alta"),
                                                 "10.30.2.20": answer("media"), "10.30.2.44": answer("baja")}))
        self.assertEqual([r["ip"] for r in rows], ["10.30.1.10", "10.30.1.21", "10.30.2.20", "10.30.2.44"])

    def test_no_hosts_means_no_calls(self):
        def never(prompt):
            raise AssertionError("no debería llamar al modelo")
        self.assertEqual(prioridad.analizar([], never), [])
