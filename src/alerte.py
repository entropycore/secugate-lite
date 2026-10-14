from src.contrat import Alerte, Signal, Verdict
import re

def choisir_canal(niveau: str) -> str:
    if niveau == "CRITIQUE":
        return "TELEPHONE"
    elif niveau == "ELEVEE":
        return "SLACK"
    elif niveau == "MOYENNE":
        return "EMAIL"
    elif niveau == "FAIBLE":
        return "TABLEAU"
    else:
        raise ValueError(f"Niveau inconnu : {niveau}")

def rediger(sig: Signal, verdict: Verdict) -> str:
    sources_str = ", ".join(verdict.sources)
    
    # 5 lignes exactes séparées par des sauts de ligne
    lignes = [
        f"[{verdict.niveau}] Cible: {sig.cible}",
        f"Signal: {sig.message}",
        f"Explication: {verdict.explication}",
        f"Action proposee: {verdict.action}",
        f"Sources: {sources_str}"
    ]
    return "\n".join(lignes)

def alerter(sig: Signal, verdict: Verdict, journal: list) -> Alerte:
    canal = choisir_canal(verdict.niveau)
    texte = rediger(sig, verdict)
    
    alerte = Alerte(
        signal_id=sig.id,
        canal=canal,
        destinataire="equipe-secu",
        texte=texte
    )
    
    journal.append(alerte)
    sig.statut = "ALERTE"
    return alerte

def valider_action(verdict: Verdict, reponse: str) -> bool:
    if not verdict.sensible:
        return True
        
    rep = reponse.strip().lower()
    return rep in ["o", "oui", "ok", "yes"]