import unittest
from src.collecte import masquer_ip

class TestCollecte(unittest.TestCase):
    def test_masquer_ip(self):
        self.assertEqual(masquer_ip("192.168.1.15"), "192.168.1.x")
        with self.assertRaises(ValueError):
            masquer_ip("192.168.1")

if __name__ == "__main__":
    unittest.main()