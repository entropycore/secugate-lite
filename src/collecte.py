from src.contrat import Signal
import re

def masquer_ip(ip: str) -> str:
    parties = ip.split('.')
    if len(parties) != 4:
        raise ValueError("L'adresse IP doit avoir 4 parties séparées par des points.")
    parties[3] = 'x'
    return '.'.join(parties)
def masquer_parametres(chemin: str) -> str:
    # (?i) = insensible à la casse. Remplace la valeur par [MASQUE] jusqu'au prochain & ou espace
    return re.sub(r'(?i)(token|password|session|key)=[^&\s]+', r'\1=[MASQUE]', chemin)

def normaliser_acces(ligne: str, numero: int, cible: str = "web-app") -> Signal:
    parties = ligne.strip().split()
    if len(parties) < 6:
        raise ValueError("La ligne a moins de 6 champs.")
    
    date, heure, ip, methode, chemin, statut = parties[0:6]
    timestamp = f"{date}T{heure}Z"
    
    chemin_sans_param = chemin.split('?')[0]
    type_sig = "LOGIN_ECHEC" if chemin_sans_param == "/login" and statut in ["401", "403"] else "ACCES"
    
    if statut.startswith("5"):
        gravite = "ELEVEE"
    elif statut.startswith("4"):
        gravite = "MOYENNE"
    else:
        gravite = "FAIBLE"
        
    ip_masquee = masquer_ip(ip)
    chemin_masque = masquer_parametres(chemin)
    message = f"{methode} {chemin_masque} -> {statut} depuis {ip_masquee}"
    
    return Signal(
        id=f"SIG-{numero:05d}",
        timestamp=timestamp,
        source="ACCES",
        ip=ip,
        cible=cible,
        type=type_sig,
        gravite=gravite,
        message=message
    )

def normaliser_scan(rapport: dict, numero: int) -> Signal:
    cles_requises = ["rule", "component", "severity", "message", "date"]
    for cle in cles_requises:
        if cle not in rapport:
            raise ValueError(f"Clé manquante dans le rapport: {cle}")
            
    sev = rapport["severity"].lower()
    map_gravite = {
        "blocker": "CRITIQUE",
        "critical": "ELEVEE",
        "major": "MOYENNE",
        "minor": "FAIBLE"
    }
    gravite = map_gravite.get(sev, "FAIBLE")
    message = f"Faille {rapport['rule']} : {rapport['message']}"
    
    return Signal(
        id=f"SIG-{numero:05d}",
        timestamp=rapport["date"],
        source="SCAN",
        ip="",
        cible=rapport["component"],
        type="FAILLE",
        gravite=gravite,
        message=message
    )