import unittest
from src.contrat import PROCEDURES, Signal
from src.detection import analyser, chercher_procedures, compter_echecs, est_deja_vu, evaluer

def sig(type_="ACCES", gravite="FAIBLE", message="GET /home -> 200", ip="10.0.0.5"):
    return Signal(
        id="SIG-00001", 
        timestamp="2026-10-05T10:00:00Z", 
        source="ACCES", 
        ip=ip, 
        cible="web-app",
        type=type_, 
        gravite=gravite, 
        message=message
    )

class TestDetection(unittest.TestCase):
    def test_doublon(self):
        vus = set()
        s = sig()
        self.assertFalse(est_deja_vu(s, vus))
        self.assertTrue(est_deja_vu(s, vus))

    def test_compter_echecs(self):
        compteur = {}
        s = sig("LOGIN_ECHEC", ip="192.168.1.15")
        self.assertEqual(compter_echecs(s, compteur), 1)
        self.assertEqual(compter_echecs(s, compteur), 2)
        
        # Un simple ACCES ne doit pas augmenter le compteur
        s_normal = sig("ACCES", ip="192.168.1.15")
        self.assertEqual(compter_echecs(s_normal, compteur), 2)

    def test_chercher_procedures(self):
        s = sig(message="Un pb de LOGIN detecte")
        procs = chercher_procedures(s, PROCEDURES)
        self.assertEqual(len(procs), 1)
        self.assertTrue(procs[0].startswith("Echecs de connexion"))

    def test_evaluer_echecs_login(self):
        e = sig("LOGIN_ECHEC", "MOYENNE")
        self.assertEqual(evaluer(e, 5), "CRITIQUE")
        self.assertEqual(evaluer(e, 4), "MOYENNE")
        
    def test_evaluer_autre_signal(self):
        e = sig("FAILLE", "ELEVEE")
        self.assertEqual(evaluer(e, 0), "ELEVEE")

    def test_analyser(self):
        s = sig("LOGIN_ECHEC", "MOYENNE", "POST /login 401", "192.168.1.15")
        verdict = analyser(s, PROCEDURES, nb_echecs=5)
        
        self.assertEqual(verdict.signal_id, "SIG-00001")
        self.assertEqual(verdict.niveau, "CRITIQUE")
        self.assertEqual(verdict.action, "Bloquer l'IP 192.168.1.15")
        self.assertTrue(verdict.sensible)
        self.assertEqual(s.statut, "ANALYSE")

if __name__ == "__main__":
    unittest.main()