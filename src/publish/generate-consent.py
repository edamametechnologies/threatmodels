#!/usr/bin/env python3
"""Generate score-reporting consent pages from the threat-model JSON.

Static operator notices live as hand-edited files under consent/. The
privacy-detailed pages list every check title from the current model, so they
are regenerated here whenever `make update` runs. Downstream
edamame_foundation/update-threats.sh embeds the whole consent/ tree.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONSENT_DIR = ROOT / "consent"

SOURCES = ("Windows", "macOS", "iOS", "Linux", "Android")
AI_SOURCES = ("Windows", "macOS", "Linux")
LOCALES = ("EN", "FR")

PRIVACY_HEADER_EN = """* Your machine unique identifier
* Your operating system name and version
* Your public IPv4 address and/or IPv6 address
* Your MAC address if available
* Your peer IDs for your VPN or ZTNA connections if available
* The domain you are connected to
* Your username in that domain
* Your score as a single numerical value"""

PRIVACY_HEADER_FR = """* L'identifiant unique de votre machine
* Le nom et la version de votre système d'exploitation
* Votre adresse IPv4 et/ou IPv6 publique
* Votre adresse MAC si disponible
* Vos identifiants de pairs pour vos connexions VPN ou ZTNA si disponibles
* Le domaine auquel vous êtes connecté
* Votre nom d'utilisateur dans ce domaine
* Votre score sous forme d'une valeur numérique"""

AI_SECTION_EN = """* The AI details of this machine:
  * AI setup of this machine, sent in every report while AI details are shared, even when no AI check is failing
    * The operating system family, and whether the assessed user account is an administrator, runs elevated or can become root without a password. The account name itself is not sent
    * The governance harnesses EDAMAME knows, for example `nono` or `srt`, and whether each one is installed
    * For every AI coding agent EDAMAME supports, for example `cursor` or `claude_code`:
      * Whether it is installed and whether its transcript observer is running
      * Whether it runs in a sandbox, the sandbox mechanism and its file access scope
      * Which risk amplifiers apply, for example `passwordless_root`, `critical_subprocess` or `secret_exposure`
      * The file names, without paths or arguments, of the sensitive programs it launched, for example `ssh`
      * The categories of secrets found in its transcripts, for example `aws_credentials`, never the secrets themselves
      * Every MCP server it declares, whether exposed or not: the configured server name, the transport, the exposure scope, the authentication strength, whether it is EDAMAME's own server, and the severity and rule names of any risk found on it
  * For each failing AI agent security check
    * The name of the check, the agent it concerns, and the conditions that made it fail: a risk amplifier, a sensitive program name, an MCP server name and exposure rule, a secret category, a missing or bypassed governance harness, or a paused transcript observer
    * For each attack pattern finding: the detector that raised it, its identifier (a hash), its severity, the file names, without paths, of the process and of its parent process, the destination and port, the detection basis, the framework reference, whether you dismissed it on this device, and whether an AI model reviewed it
      * The destination is the domain name or, when there is none, the IP address. A private, local-network or loopback destination is sent only as that category, for example `private network`, never as its address or name
      * For the files the finding touched: the category and the file name, without its folder, of each file EDAMAME's sensitive-file list recognizes, for example `ssh:id_ed25519`, and only the number of other files. A file in your home folder whose name contains your account name is sent as its category alone
      * When an AI agent re-ran a denied command under another spelling: the names of the programs involved, for example `curl`, without their arguments
    * For each behavioral divergence finding: its category, identifier, severity, the file name of the process, the agent concerned, the phrase the engine uses for what triggered it, for example `unexpected sensitive file access with unexplained external egress`, and the number of unexpected sensitive files (not their paths)
    * For each Assistant action waiting for your review: its identifier, its type and its priority
    * Whether the attack pattern detector, the divergence engine or the Assistant is switched off
    * The descriptions EDAMAME shows for these findings on this device are not sent: EDAMAME Hub shows a summary built from the items above

Agent transcripts, prompts, model responses, file contents, full file paths, command arguments, environment variable values and secret values are never reported."""

AI_SECTION_FR = """* Les détails IA de cette machine :
  * Configuration IA de cette machine, envoyée dans chaque rapport tant que les détails IA sont partagés, même quand aucun test IA n'est en échec
    * La famille du système d'exploitation, et si le compte utilisateur évalué est administrateur, s'exécute avec des droits élevés ou peut devenir root sans mot de passe. Le nom du compte lui-même n'est pas envoyé
    * Les harnais de gouvernance connus d'EDAMAME, par exemple `nono` ou `srt`, et si chacun est installé
    * Pour chaque agent de codage IA pris en charge par EDAMAME, par exemple `cursor` ou `claude_code` :
      * S'il est installé et si son observateur de transcriptions est actif
      * S'il s'exécute dans un bac à sable, le mécanisme de ce bac à sable et son étendue d'accès aux fichiers
      * Les amplificateurs de risque qui s'appliquent, par exemple `passwordless_root`, `critical_subprocess` ou `secret_exposure`
      * Les noms de fichier, sans chemin ni arguments, des programmes sensibles qu'il a lancés, par exemple `ssh`
      * Les catégories de secrets détectés dans ses transcriptions, par exemple `aws_credentials`, jamais les secrets eux-mêmes
      * Chaque serveur MCP qu'il déclare, exposé ou non : le nom configuré du serveur, le transport, l'étendue d'exposition, le niveau d'authentification, s'il s'agit du serveur d'EDAMAME, ainsi que la sévérité et le nom des règles de tout risque détecté sur ce serveur
  * Pour chaque test de sécurité IA en échec
    * Le nom du test, l'agent concerné, et les conditions qui l'ont fait échouer : un amplificateur de risque, un nom de programme sensible, un nom de serveur MCP et sa règle d'exposition, une catégorie de secret, un harnais de gouvernance absent ou contourné, ou un observateur de transcriptions en pause
    * Pour chaque constat de schéma d'attaque : le détecteur qui l'a levé, son identifiant (une empreinte), sa sévérité, les noms de fichier, sans chemin, du processus et de son processus parent, la destination et le port, la base de détection, la référence de cadre, si vous l'avez écarté sur cet appareil, et si un modèle d'IA l'a examiné
      * La destination est le nom de domaine ou, à défaut, l'adresse IP. Une destination privée, du réseau local ou de bouclage n'est envoyée que sous cette catégorie, par exemple `private network`, jamais sous son adresse ni son nom
      * Pour les fichiers concernés par le constat : la catégorie et le nom de fichier, sans son dossier, de chaque fichier reconnu par la liste de fichiers sensibles d'EDAMAME, par exemple `ssh:id_ed25519`, et seulement le nombre des autres fichiers. Un fichier de votre dossier personnel dont le nom contient le nom de votre compte n'est envoyé que sous sa catégorie
      * Lorsqu'un agent IA a relancé une commande interdite sous une autre forme : les noms des programmes concernés, par exemple `curl`, sans leurs arguments
    * Pour chaque constat de divergence comportementale : sa catégorie, son identifiant, sa sévérité, le nom de fichier du processus, l'agent concerné, la formule du moteur pour ce qui l'a déclenché, par exemple `unexpected sensitive file access with unexplained external egress`, et le nombre de fichiers sensibles inattendus (pas leurs chemins)
    * Pour chaque action de l'Assistant en attente de votre validation : son identifiant, son type et sa priorité
    * Si le détecteur de schémas d'attaque, le moteur de divergence ou l'Assistant est désactivé
    * Les descriptions qu'EDAMAME affiche pour ces constats sur cet appareil ne sont pas envoyées : EDAMAME Hub affiche un résumé construit à partir des éléments ci-dessus

Les transcriptions d'agents, les invites, les réponses des modèles, le contenu des fichiers, les chemins complets des fichiers, les arguments des commandes, les valeurs des variables d'environnement et les valeurs des secrets ne sont jamais rapportés."""


def threat_titles(model: dict, locale: str) -> list[str]:
    titles: list[str] = []
    for metric in model.get("metrics", []):
        chosen = ""
        fallback = ""
        for localized in metric.get("description", []):
            if localized.get("locale") == locale:
                chosen = localized.get("title") or ""
                break
            if localized.get("locale") == "EN" and not fallback:
                fallback = localized.get("title") or ""
        title = chosen or fallback
        if title:
            titles.append(title)
    return titles


def render_page(source: str, locale: str, titles: list[str], ai_details: bool) -> str:
    french = locale == "FR"
    if ai_details:
        heading = (
            f"{source} Politique de Confidentialité du Score Détaillé avec Détails IA ({locale})"
            if french
            else f"{source} Detailed Score Privacy Policy with AI Details ({locale})"
        )
    else:
        heading = (
            f"{source} Politique de Confidentialité du Score Détaillé ({locale})"
            if french
            else f"{source} Detailed Score Privacy Policy ({locale})"
        )

    intro = (
        "En rapportant un score détaillé, vous acceptez de partager les informations suivantes avec EDAMAME :"
        if french
        else "By reporting a detailed score, you agree to share the following information with EDAMAME:"
    )
    header = PRIVACY_HEADER_FR if french else PRIVACY_HEADER_EN
    checks_label = (
        "* Votre score sous forme d'un vecteur de valeurs booléennes résultant des tests de sécurité suivants :"
        if french
        else "* Your score as a detailed vector of boolean values resulting on the following security checks:"
    )
    checks = "\n".join(f"  * {title}" for title in titles)
    if not checks:
        checks = (
            "  * Les tests de sécurité définis par le modèle de menace chargé sur cet appareil"
            if french
            else "  * The security checks defined by the threat model loaded on this device"
        )

    model_name = f"threatmodel-{source}"
    model_url = f"https://github.com/edamametechnologies/threatmodels/blob/main/{model_name}.json"
    wiki_url = f"https://github.com/edamametechnologies/threatmodels/wiki/{model_name}-{locale}"
    trailer = (
        f"""
Ces informations sont utilisées uniquement par EDAMAME et ne sont pas partagées avec des tiers.

Ces informations sont collectées à l'aide d'un "modèle de menace" public qui garantit de ne pas violer votre vie privée.

Le modèle de menace peut être consulté à l'adresse [{model_url}]({model_url}).

Le wiki du modèle de menace peut être consulté à l'adresse [{wiki_url}]({wiki_url}).

Si vous n'êtes pas d'accord avec cette politique, veuillez ne pas rapporter votre score."""
        if french
        else f"""
This information is used solely by EDAMAME and is not shared with any third party.

This information is gathered using a public "threat model" that is guaranteed not to violate your privacy.

The threat model can be seen at [{model_url}]({model_url}).

The threat model wiki can be seen at [{wiki_url}]({wiki_url}).

If you do not agree with this policy, please do not report your score."""
    )

    parts = [heading, "=" * len(heading), "", intro, header, checks_label, checks]
    if ai_details:
        parts.extend(["", AI_SECTION_FR if french else AI_SECTION_EN])
    parts.append(trailer)
    return "\n".join(parts).rstrip() + "\n"


def main() -> None:
    CONSENT_DIR.mkdir(parents=True, exist_ok=True)
    written = 0
    for source in SOURCES:
        model_path = ROOT / f"threatmodel-{source}.json"
        with model_path.open(encoding="utf-8") as handle:
            model = json.load(handle)
        for locale in LOCALES:
            titles = threat_titles(model, locale)
            detailed = CONSENT_DIR / f"privacy-detailed-{source}-{locale}.md"
            detailed.write_text(render_page(source, locale, titles, False), encoding="utf-8")
            written += 1
            if source in AI_SOURCES:
                ai = CONSENT_DIR / f"privacy-detailed-ai-{source}-{locale}.md"
                ai.write_text(render_page(source, locale, titles, True), encoding="utf-8")
                written += 1
    names = sorted(path.name for path in CONSENT_DIR.glob("*.md"))
    (CONSENT_DIR / "index.txt").write_text("\n".join(names) + "\n", encoding="utf-8")
    print(f"Wrote {written} generated pages; index lists {len(names)} files under {CONSENT_DIR}")


if __name__ == "__main__":
    main()
