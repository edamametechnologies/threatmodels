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

AI_SECTION_EN = """* The details of each failing AI agent security check listed above:
  * For every AI coding agent EDAMAME supports, whether it is installed on this machine and whether its transcript observer is running
  * The name of the agent a failure belongs to, for example `cursor` or `claude_code`
  * The name of the governance harness that agent declares, for example `nono` or `srt`
  * The name of the risk amplifier that fired, for example `passwordless_root`, `critical_subprocess` or `secret_exposure`
  * The file name, without its path or its arguments, of a sensitive program the agent launched, for example `ssh`
  * The configured name of an MCP server found to be exposed, for example `gojiberry`, together with the exposure rule that fired, for example `mcp_public_no_strong_auth`. MCP servers that are not exposed are never named
  * The category of a secret found in the agent transcript, for example `aws_credentials`, never the secret itself

Agent transcripts, prompts, model responses, file contents, command arguments, environment variable values and secret values are never reported."""

AI_SECTION_FR = """* Le détail de chaque test de sécurité IA en échec parmi ceux listés ci-dessus :
  * Pour chaque agent de codage IA pris en charge par EDAMAME, s'il est installé sur cette machine et si son observateur de transcriptions est actif
  * Le nom de l'agent concerné par l'échec, par exemple `cursor` ou `claude_code`
  * Le nom du harnais de gouvernance déclaré par cet agent, par exemple `nono` ou `srt`
  * Le nom de l'amplificateur de risque déclenché, par exemple `passwordless_root`, `critical_subprocess` ou `secret_exposure`
  * Le nom de fichier, sans son chemin ni ses arguments, d'un programme sensible lancé par l'agent, par exemple `ssh`
  * Le nom configuré d'un serveur MCP détecté comme exposé, par exemple `gojiberry`, accompagné de la règle d'exposition déclenchée, par exemple `mcp_public_no_strong_auth`. Les serveurs MCP non exposés ne sont jamais nommés
  * La catégorie d'un secret détecté dans la transcription de l'agent, par exemple `aws_credentials`, jamais le secret lui-même

Les transcriptions d'agents, les invites, les réponses des modèles, le contenu des fichiers, les arguments de commande, les valeurs des variables d'environnement et les valeurs des secrets ne sont jamais rapportés."""


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
