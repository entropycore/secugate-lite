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