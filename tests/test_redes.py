import unittest
from unittest.mock import patch

from dedalo import redes

IPCONFIG = """
Adaptador de Ethernet Ethernet:
   Dirección IPv4. . . . . . . . . . . . . . : 192.168.1.50
   Máscara de subred . . . . . . . . . . . . : 255.255.255.0
Adaptador de túnel Loopback:
   Dirección IPv4. . . . . . . . . . . . . . : 127.0.0.1
   Máscara de subred . . . . . . . . . . . . : 255.0.0.0
"""

IP_ADDR = ("1: lo    inet 127.0.0.1/8 scope host lo\n"
           "2: eth0  inet 10.30.4.7/24 brd 10.30.4.255 scope global eth0\n"
           "3: eth0  inet6 fe80::1/64 scope link\n")

# ipconfig real en Windows en español: la consola suele devolver los acentos rotos
# («Dirección»→«Direcci?n», «Máscara»→«M?scara»). Las etiquetas no son fiables; el valor sí.
IPCONFIG_ACENTOS_ROTOS = (
    "Adaptador de Ethernet Ethernet:\n"
    "   Direcci�n IPv4. . . . . . . . . . . . . . : 192.168.1.41\n"
    "   M�scara de subred . . . . . . . . . . . . : 255.255.255.0\n"
    "Adaptador de t�nel Loopback:\n"
    "   Direcci�n IPv4. . . . . . . . . . . . . . : 127.0.0.1\n"
    "   M�scara de subred . . . . . . . . . . . . : 255.0.0.0\n")


class RedesTests(unittest.TestCase):
    def test_parses_ipconfig_and_drops_loopback(self):
        self.assertEqual(redes.cidrs(IPCONFIG), ["192.168.1.0/24"])

    def test_parses_ip_addr_and_drops_loopback_and_link_local(self):
        self.assertEqual(redes.cidrs(IP_ADDR), ["10.30.4.0/24"])

    def test_parses_ipconfig_even_with_garbled_accents(self):
        # La máscara se reconoce por su valor, no por la etiqueta: funciona con los acentos rotos.
        self.assertEqual(redes.cidrs(IPCONFIG_ACENTOS_ROTOS), ["192.168.1.0/24"])

    def test_detectar_returns_empty_when_the_command_fails(self):
        with patch("dedalo.redes._ejecutar", side_effect=OSError("no ipconfig")):
            self.assertEqual(redes.detectar(), [])


if __name__ == "__main__":
    unittest.main()
