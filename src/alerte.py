from src.contrat import Alerte, Signal, Verdict

CANAUX = {
    "CRITIQUE": "TELEPHONE",
    "ELEVEE": "SLACK",
    "MOYENNE": "EMAIL",
    "FAIBLE": "TABLEAU",
}


def choisir_canal(niveau: str) -> str:
    if niveau not in CANAUX:
        raise ValueError(f"Niveau inconnu : {niveau}")
    return CANAUX[niveau]


def rediger(sig: Signal, verdict: Verdict) -> str:
    sources_str = ", ".join(verdict.sources)
    lignes = [
        f"[{verdict.niveau}] Cible : {sig.cible}",
        f"Signal : {sig.message}",
        f"Explication : {verdict.explication}",
        f"Action proposee : {verdict.action}",
        f"Sources : {sources_str}",
    ]
    return "\n".join(lignes)


def alerter(sig: Signal, verdict: Verdict, journal: list) -> Alerte:
    raise NotImplementedError


def valider_action(verdict: Verdict, reponse: str) -> bool:
    raise NotImplementedError