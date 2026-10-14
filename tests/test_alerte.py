import unittest
from src.alerte import alerter, choisir_canal, rediger, valider_action
from src.contrat import Signal, Verdict

def exemple(sensible=True, niveau="CRITIQUE"):
    s = Signal(
        id="SIG-00125", 
        timestamp="2026-10-05T10:01:31Z", 
        source="ACCES", 
        ip="192.168.1.15",
        cible="web-app", 
        type="LOGIN_ECHEC", 
        gravite="MOYENNE",
        message="POST /login -> 401 depuis 192.168.1.x"
    )
    v = Verdict(
        signal_id="SIG-00125", 
        niveau=niveau, 
        explication="Echecs de connexion",
        action="Bloquer l'IP 192.168.1.15", 
        sensible=sensible, 
        sources=["ACCES"]
    )
    return s, v

class TestAlerte(unittest.TestCase):
    def test_canaux(self):
        self.assertEqual(choisir_canal("CRITIQUE"), "TELEPHONE")
        self.assertEqual(choisir_canal("ELEVEE"), "SLACK")
        self.assertEqual(choisir_canal("MOYENNE"), "EMAIL")
        self.assertEqual(choisir_canal("FAIBLE"), "TABLEAU")
        with self.assertRaises(ValueError):
            choisir_canal("INCONNU")

    def test_rediger(self):
        s, v = exemple()
        texte = rediger(s, v)
        lignes = texte.split('\n')
        self.assertEqual(len(lignes), 5)
        self.assertEqual(lignes[0], "[CRITIQUE] Cible: web-app")
        self.assertEqual(lignes[3], "Action proposee: Bloquer l'IP 192.168.1.15")

    def test_alerter(self):
        s, v = exemple()
        journal = []
        alerte = alerter(s, v, journal)
        
        self.assertEqual(alerte.canal, "TELEPHONE")
        self.assertEqual(alerte.destinataire, "equipe-secu")
        self.assertEqual(len(journal), 1)
        self.assertEqual(s.statut, "ALERTE")

    def test_validation(self):
        s, v = exemple(sensible=True)
        self.assertTrue(valider_action(v, " OUI "))
        self.assertTrue(valider_action(v, "ok"))
        self.assertTrue(valider_action(v, "yes"))
        self.assertTrue(valider_action(v, "o"))
        self.assertFalse(valider_action(v, "n"))
        self.assertFalse(valider_action(v, "non"))
        
    def test_validation_non_sensible(self):
        s, v = exemple(sensible=False)
        self.assertTrue(valider_action(v, "non")) # Toujours True si non sensible

if __name__ == "__main__":
    unittest.main()