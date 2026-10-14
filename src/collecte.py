from src.contrat import Signal
import re

def masquer_ip(ip: str) -> str:
    parties = ip.split('.')
    if len(parties) != 4:
        raise ValueError("L'adresse IP doit avoir 4 parties séparées par des points.")
    parties[3] = 'x'
    return '.'.join(parties)