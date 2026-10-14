from src.contrat import Signal, Verdict

def est_deja_vu(sig: Signal, vus: set) -> bool:
    # La clé demandée par le contrat
    cle = (sig.timestamp, sig.source, sig.ip, sig.cible, sig.type, sig.message)
    if cle in vus:
        return True
    vus.add(cle)
    return False

def compter_echecs(sig: Signal, compteur: dict) -> int:
    if sig.type == "LOGIN_ECHEC":
        # Ajoute 1 ou initialise à 1 si l'IP n'existe pas encore
        compteur[sig.ip] = compteur.get(sig.ip, 0) + 1
        return compteur[sig.ip]
    return compteur.get(sig.ip, 0)

def chercher_procedures(sig: Signal, base: dict) -> list:
    msg_min = sig.message.lower()
    procedures_trouvees = []
    # Parcourt le dictionnaire dans l'ordre
    for mot_cle, procedure in base.items():
        if mot_cle.lower() in msg_min:
            procedures_trouvees.append(procedure)
    return procedures_trouvees

def evaluer(sig: Signal, nb_echecs: int = 0) -> str:
    if sig.type == "LOGIN_ECHEC":
        return "CRITIQUE" if nb_echecs >= 5 else "MOYENNE"
    return sig.gravite

def analyser(sig: Signal, base: dict, nb_echecs: int = 0) -> Verdict:
    niveau = evaluer(sig, nb_echecs)
    
    # Gestion des procédures
    procs = chercher_procedures(sig, base)
    if procs:
        explication = " ".join(procs)
    else:
        explication = "Cause inconnue : analyse manuelle requise"
        
    # Gestion des actions
    if sig.type == "LOGIN_ECHEC" and niveau == "CRITIQUE":
        action = f"Bloquer l'IP {sig.ip}"
    elif sig.type == "FAILLE":
        action = f"Corriger la faille dans {sig.cible}"
    else:
        action = "Surveiller"
        
    sensible = niveau in ["ELEVEE", "CRITIQUE"]
    sig.statut = "ANALYSE"
    
    return Verdict(
        signal_id=sig.id,
        niveau=niveau,
        explication=explication,
        action=action,
        sensible=sensible,
        sources=[sig.source]
    )