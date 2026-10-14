import re
from src.contrat import Signal

def masquer_ip(ip: str) -> str:
    parties = ip.split('.')
    if len(parties) != 4:
        raise ValueError("L'adresse IP doit avoir 4 parties séparées par des points.")
    parties[-1] = 'x'
    return '.'.join(parties)

def masquer_parametres(chemin: str) -> str:
    # (?i) rend la recherche insensible à la casse pour token, password, session, key
    return re.sub(r'(?i)(token|password|session|key)=([^&\s]+)', r'\1=[MASQUE]', chemin)

def normaliser_acces(ligne: str, numero: int, cible: str = "web-app") -> Signal:
    champs = ligne.strip().split()
    if len(champs) < 6:
        raise ValueError("La ligne a moins de 6 champs.")
    
    date, heure, ip_brute, methode, chemin, statut = champs[:6]
    
    # Détermination du type
    chemin_base = chemin.split('?')[0]
    if chemin_base == "/login" and statut in ["401", "403"]:
        type_sig = "LOGIN_ECHEC"
    else:
        type_sig = "ACCES"
        
    # Détermination de la gravité
    if statut.startswith('5'):
        gravite = "ELEVEE"
    elif statut.startswith('4'):
        gravite = "MOYENNE"
    else:
        gravite = "FAIBLE"
        
    ip_masquee = masquer_ip(ip_brute)
    chemin_masque = masquer_parametres(chemin)
    message = f"{methode} {chemin_masque} -> {statut} depuis {ip_masquee}"
    
    return Signal(
        id=f"SIG-{numero:05d}",
        timestamp=f"{date}T{heure}Z",
        source="ACCES",
        ip=ip_brute,
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
            
    sev_brute = str(rapport["severity"]).lower()
    mapping_gravite = {
        "blocker": "CRITIQUE",
        "critical": "ELEVEE",
        "major": "MOYENNE",
        "minor": "FAIBLE"
    }
    gravite = mapping_gravite.get(sev_brute, "FAIBLE")
    
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