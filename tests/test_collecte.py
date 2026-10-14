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

    
    def test_normaliser_acces(self):
        ligne = "2026-10-05 10:01:10 192.168.1.15 POST /login 401"
        sig = normaliser_acces(ligne, 42)
        self.assertEqual(sig.id, "SIG-00042")
        self.assertEqual(sig.timestamp, "2026-10-05T10:01:10Z")
        self.assertEqual(sig.type, "LOGIN_ECHEC")
        self.assertEqual(sig.gravite, "MOYENNE")
        self.assertEqual(sig.message, "POST /login -> 401 depuis 192.168.1.x")

    
    def test_normaliser_scan(self):
        rapport = {
            "rule": "S3649", "component": "backend", 
            "severity": "blocker", "message": "injection SQL possible", 
            "date": "2026-10-05T10:05:00Z"
        }
        sig = normaliser_scan(rapport, 1)
        self.assertEqual(sig.id, "SIG-00001")
        self.assertEqual(sig.type, "FAILLE")
        self.assertEqual(sig.gravite, "CRITIQUE")
        self.assertEqual(sig.message, "Faille S3649 : injection SQL possible")

if __name__ == "__main__":
    unittest.main()