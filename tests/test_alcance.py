"""Reglas de alcance (docs/CONTRATOS.md 0.3) que no dependen de ningún otro módulo."""

import unittest

from dedalo import targets


class AlcanceTests(unittest.TestCase):
    def test_una_ipv4_escrita_como_ipv6_mapeada_no_esquiva_la_exclusion(self):
        # ::ffff:10.0.0.5 es el mismo equipo que 10.0.0.5: la exclusión gana, se escriba como se escriba.
        alcance = targets.Scope(["::/0", "10.0.0.0/24"], ["10.0.0.5/32"])
        self.assertEqual(alcance.status("::ffff:10.0.0.5"), targets.Scope.EXCLUDED)
        alcance = targets.Scope(["10.0.0.0/24"], ["::ffff:10.0.0.5/128"])
        self.assertEqual(alcance.status("10.0.0.5"), targets.Scope.EXCLUDED)
        # Y una regla IPv6 amplia no mete en alcance una IPv4 que no se incluyó.
        self.assertEqual(targets.Scope(["::/0"]).status("::ffff:10.0.0.6"), targets.Scope.OUT)
        self.assertEqual(targets.Scope(["10.0.0.0/24"]).status("::ffff:10.0.0.6"), targets.Scope.IN)


if __name__ == "__main__":
    unittest.main()
