import socket
import struct
import threading
import time
import unittest
from unittest.mock import patch

from nmapshot import descubrimiento, targets


class FakeDNS:
    """Servidor DNS mínimo en 127.0.0.1 para probar el modo «servidores»."""

    def __init__(self, rcode=0, answers=1, reply_id=None, other_source=False):
        self.rcode, self.answers, self.reply_id = rcode, answers, reply_id
        self.queries = []
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        # Con other_source la respuesta sale de otro puerto, como si la diera otra máquina.
        self.sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if other_source else self.socket
        if other_source:
            self.sender.bind(("127.0.0.1", 0))
        self.socket.settimeout(0.2)
        self.port = self.socket.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while self.running:
            try:
                data, address = self.socket.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            self.queries.append(data)
            query_id = self.reply_id if self.reply_id is not None else struct.unpack(">H", data[:2])[0]
            header = struct.pack(">HHHHHH", query_id, 0x8180 | self.rcode, 1, self.answers, 0, 0)
            self.sender.sendto(header + data[12:], address)

    def close(self):
        self.running = False
        self.thread.join(2)
        self.socket.close()
        self.sender.close()


class ExpandTests(unittest.TestCase):
    def test_lists_usable_hosts_without_duplicates(self):
        self.assertEqual(descubrimiento.expand(["192.0.2.0/30"]), ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(descubrimiento.expand(["192.0.2.5/32"]), ["192.0.2.5"])
        self.assertEqual(len(descubrimiento.expand(["192.0.2.0/24"])), 254)
        # Rangos solapados: cada dirección una sola vez y en orden.
        self.assertEqual(descubrimiento.expand(["192.0.2.0/30", "192.0.2.0/29"]),
                         ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6"])

    def test_refuses_ranges_too_large_to_sweep(self):
        for networks in (["10.0.0.0/8"], ["2001:db8::/64"], ["192.0.2.0/24", "10.0.0.0/8"]):
            with self.subTest(networks=networks), self.assertRaisesRegex(ValueError, "hasta 65.536"):
                descubrimiento.expand(networks)


class QueryTests(unittest.TestCase):
    def test_packet_is_a_single_a_record_question(self):
        packet = descubrimiento.query_packet("ejemplo.test", 0x1234)
        self.assertEqual(struct.unpack(">HHHHHH", packet[:12]), (0x1234, 0x0100, 1, 0, 0, 0))
        self.assertEqual(packet[12:], b"\x07ejemplo\x04test\x00" + struct.pack(">HH", 1, 1))
        for domain in ("", ".", "x" * 64 + ".test"):
            with self.subTest(domain=domain), self.assertRaisesRegex(ValueError, "Dominio inválido"):
                descubrimiento.query_packet(domain, 1)

    def test_detects_a_dns_server_and_reports_its_answer(self):
        server = FakeDNS()
        try:
            answered, detail, error = descubrimiento.dns_server("127.0.0.1", "ejemplo.test", 2, server.port)
        finally:
            server.close()
        self.assertEqual((answered, error), (True, ""))
        self.assertEqual(detail, "correcta; 1 respuesta(s)")

    def test_reports_refusals_as_a_server_that_answers(self):
        server = FakeDNS(rcode=5, answers=0)
        try:
            answered, detail, _ = descubrimiento.dns_server("127.0.0.1", "ejemplo.test", 2, server.port)
        finally:
            server.close()
        self.assertTrue(answered)
        self.assertEqual(detail, "consulta rechazada; 0 respuesta(s)")

    def test_ignores_replies_that_do_not_match_the_query(self):
        server = FakeDNS(reply_id=0xBEEF)
        try:
            answered, _, error = descubrimiento.dns_server("127.0.0.1", "ejemplo.test", 0.4, server.port)
        finally:
            server.close()
        self.assertEqual((answered, error), (False, ""))
        self.assertTrue(server.queries)

    def test_ignores_a_matching_reply_from_another_address(self):
        server = FakeDNS(other_source=True)
        try:
            answered, _, error = descubrimiento.dns_server("127.0.0.1", "ejemplo.test", 0.4, server.port)
        finally:
            server.close()
        self.assertEqual((answered, error), (False, ""))
        self.assertTrue(server.queries)

    def test_silence_or_closed_port_is_not_a_server(self):
        free = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        free.bind(("127.0.0.1", 0))
        port = free.getsockname()[1]
        free.close()
        self.assertEqual(descubrimiento.dns_server("127.0.0.1", "ejemplo.test", 0.4, port), (False, "", ""))


class SweepTests(unittest.TestCase):
    def test_reverse_mode_keeps_order_and_reports_progress(self):
        names = {"192.0.2.1": ("uno.test", ""), "192.0.2.2": ("", ""), "192.0.2.3": ("tres.test", "")}
        seen = []
        with patch("nmapshot.descubrimiento.reverse_name", side_effect=lambda ip: names[ip]):
            rows = descubrimiento.sweep(list(names), "nombres", progress=lambda done, total: seen.append((done, total)))
        self.assertEqual([(row["ip"], row["nombre"], row["encontrado"]) for row in rows],
                         [("192.0.2.1", "uno.test", True), ("192.0.2.2", "", False), ("192.0.2.3", "tres.test", True)])
        self.assertEqual(sorted(seen), [(1, 3), (2, 3), (3, 3)])

    def test_delay_spaces_out_queries_even_with_several_workers(self):
        starts = []
        with patch("nmapshot.descubrimiento.reverse_name", side_effect=lambda ip: (starts.append(time.monotonic()), ("", ""))[1]):
            descubrimiento.sweep([f"192.0.2.{n}" for n in range(1, 5)], "nombres", delay=0.05, workers=4)
        self.assertEqual(len(starts), 4)
        self.assertGreaterEqual(max(starts) - min(starts), 0.12)

    def test_cancelling_stops_the_sweep_and_keeps_what_was_done(self):
        calls = []
        with patch("nmapshot.descubrimiento.reverse_name", side_effect=lambda ip: (calls.append(ip), ("", ""))[1]):
            rows = descubrimiento.sweep([f"192.0.2.{n}" for n in range(1, 40)], "nombres",
                                        workers=1, stop=lambda: len(calls) >= 3)
        self.assertEqual(len(rows), 3)
        self.assertLessEqual(len(calls), 4)

    def test_rejects_unknown_mode_and_invalid_domain_before_connecting(self):
        with patch("nmapshot.descubrimiento.dns_server", side_effect=AssertionError("no consultar")):
            with self.assertRaisesRegex(ValueError, "Modo"):
                descubrimiento.sweep(["192.0.2.1"], "otro")
            with self.assertRaisesRegex(ValueError, "Dominio inválido"):
                descubrimiento.sweep(["192.0.2.1"], "servidores", "", scope=targets.Scope(["192.0.2.0/24"]))

    def test_server_mode_requires_scope_and_never_queries_outside_it(self):
        with patch("nmapshot.descubrimiento.dns_server", side_effect=AssertionError("no consultar")),                 self.assertRaisesRegex(ValueError, "necesita el alcance"):
            descubrimiento.sweep(["192.0.2.1"], "servidores", "ejemplo.test")
        scope = targets.Scope(["192.0.2.0/30"], ["192.0.2.2"])
        queried = []
        with patch("nmapshot.descubrimiento.dns_server",
                   side_effect=lambda ip, *args: (queried.append(ip), (True, "correcta; 1 respuesta(s)", ""))[1]):
            rows = descubrimiento.sweep(["192.0.2.1", "192.0.2.2", "198.51.100.7"], "servidores", "ejemplo.test", scope=scope)
        self.assertEqual(queried, ["192.0.2.1"])
        self.assertEqual([(row["ip"], row["encontrado"], row["error"]) for row in rows], [
            ("192.0.2.1", True, ""),
            ("192.0.2.2", False, "Excluida del alcance: no se consulta"),
            ("198.51.100.7", False, "Fuera de alcance: no se consulta"),
        ])

    def test_scope_is_checked_at_query_time_not_when_planning(self):
        # Una exclusión añadida durante el barrido se respeta en las IP que faltan.
        class LiveScope:
            rules = targets.Scope(["192.0.2.0/24"])

            def status(self, ip):
                return self.rules.status(ip)

        live, queried = LiveScope(), []

        def query(ip, *args):
            queried.append(ip)
            live.rules = targets.Scope(["192.0.2.0/24"], ["192.0.2.0/24"])
            return False, "", ""

        with patch("nmapshot.descubrimiento.dns_server", side_effect=query):
            rows = descubrimiento.sweep([f"192.0.2.{n}" for n in range(1, 5)], "servidores", "ejemplo.test",
                                        scope=live, workers=1)
        self.assertEqual(queried, ["192.0.2.1"])
        self.assertEqual([row["error"] for row in rows[1:]], ["Excluida del alcance: no se consulta"] * 3)
