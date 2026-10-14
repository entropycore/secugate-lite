import unittest
from src.collecte import masquer_ip

class TestCollecte(unittest.TestCase):
    def test_masquer_ip(self):
        self.assertEqual(masquer_ip("192.168.1.15"), "192.168.1.x")
        with self.assertRaises(ValueError):
            masquer_ip("192.168.1")

    def test_masquer_parametres(self):
        self.assertEqual(
            masquer_parametres("/api?id=3&token=abc123"), 
            "/api?id=3&token=[MASQUE]"
        )

if __name__ == "__main__":
    unittest.main()