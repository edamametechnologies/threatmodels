'''Generate markdown files for each threat model into the wiki folder'''

from mdutils.mdutils import MdUtils
import json
import re

def print_action(loc, elevation, target, osName, osVersion):

    systemHeader = "Tested for"
    actionHeader = "Action"
    elevationHeader = "Elevation"
    targetHeader = "Script"
    action = "Command line"
    if loc == "FR":
        systemHeader = "Testé pour"
        action = "Ligne de commande"

    mdFile.new_line()
    mdFile.new_table(columns=4, rows=2, text=[systemHeader, actionHeader, elevationHeader, targetHeader, osName + " " + str(osVersion), action, elevation, target], text_align='left')

def md_sanitize(text):
    # Create an markdown block code by fronting it with ``` and ending it with ```
    text = "```" + text + "```"
    return text

sources = ['Windows', 'macOS', 'iOS', 'Linux', 'Android']
for source in sources:
    for loc in ("EN", "FR"):
        if loc == "FR":
            title = source + ' Modèle de Menace ' + '('+ loc + ')'
            titleP = source + ' Politique de Confidentialité du Score ' + '('+ loc + ')'
            titlePD = source + ' Politique de Confidentialité du Score Détaillé ' + '('+ loc + ')'
        else:
            title = source + ' Threat Model ' + '('+ loc + ')'
            titleP = source + ' Score Privacy Policy ' + '('+ loc + ')'
            titlePD = source + ' Detailed Score Privacy Policy ' + '('+ loc + ')'

        mdFile = MdUtils(file_name='threatmodel-' + source + '-' + loc, title=title)
        mdFileP = MdUtils(file_name='privacy-' + source + '-' + loc, title=titleP)
        mdFilePD = MdUtils(file_name='privacy-detailed-' + source + '-' + loc, title=titlePD)

        modelname = 'threatmodel-' + source
        with open(modelname + '.json', 'r') as json_file:
            model = json.load(json_file)

        # Common header
        privacyHeader = "\n* Your machine unique identifier"
        privacyHeader += "\n* Your operating system name and version"
        privacyHeader += "\n* Your public IPv4 address and/or IPv6 address"
        privacyHeader += "\n* Your MAC address if available"
        privacyHeader += "\n* Your peer IDs for your VPN or ZTNA connections if available"
        privacyHeader += "\n* The domain you are connected to"
        privacyHeader += "\n* Your username in that domain"
        privacyHeader += "\n* Your score as a single numerical value"

        privacyHeaderFR = "\n* L'identifiant unique de votre machine"
        privacyHeaderFR += "\n* Le nom et la version de votre système d'exploitation"
        privacyHeaderFR += "\n* Votre adresse IPv4 et/ou IPv6 publique"
        privacyHeaderFR += "\n* Votre adresse MAC si disponible"
        privacyHeaderFR += "\n* Vos identifiants de pairs pour vos connexions VPN ou ZTNA si disponibles"
        privacyHeaderFR += "\n* Le domaine auquel vous êtes connecté"
        privacyHeaderFR += "\n* Votre nom d'utilisateur dans ce domaine"
        privacyHeaderFR += "\n* Votre score sous forme d'une valeur numérique"

        # Common trailer
        modelurl = "https://github.com/edamametechnologies/threatmodels/blob/main/" + modelname + '.json'
        wikiurl = "https://github.com/edamametechnologies/threatmodels/wiki/" + modelname + "-" + loc
        privacyTrailer = "\n\nThis information is used solely by EDAMAME and is not shared with any third party."
        privacyTrailer += "\n\nThis information is gathered using a public \"threat model\" that is guaranteed not to violate your privacy."
        privacyTrailer += "\n\nThe threat model can be seen at [" + modelurl + "](" + modelurl + ")."
        privacyTrailer += "\n\nThe threat model wiki can be seen at [" + wikiurl + "](" + wikiurl + ")."
        privacyTrailer += "\n\nIf you do not agree with this policy, please do not report your score."

        privacyTrailerFR = "\n\nCes informations sont utilisées uniquement par EDAMAME et ne sont pas partagées avec des tiers."
        privacyTrailerFR += "\n\nCes informations sont collectées à l'aide d'un \"modèle de menace\" public qui garantit de ne pas violer votre vie privée."
        privacyTrailerFR += "\n\nLe modèle de menace peut être consulté à l'adresse [" + modelurl + "](" + modelurl + ")."
        privacyTrailerFR += "\n\nLe wiki du modèle de menace peut être consulté à l'adresse [" + wikiurl + "](" + wikiurl + ")."
        privacyTrailerFR += "\n\nSi vous n'êtes pas d'accord avec cette politique, veuillez ne pas rapporter votre score."

        # Write the Score Privacy policy (machine UUID, OS name, OS version IPv4, IPv6, domain, username, score as a single numerical value)
        privacyPolicy = "By reporting a score, you agree to share the following information with EDAMAME:"
        privacyPolicy += privacyHeader
        privacyPolicy += privacyTrailer
        
        # French version
        privacyPolicyFR = "En rapportant un score, vous acceptez de partager les informations suivantes avec EDAMAME :"
        privacyPolicyFR += privacyHeaderFR
        privacyPolicyFR += privacyTrailerFR
        

        # Write the Detailed Score Privacy policy (machine UUID, OS name, OS version IPv4, IPv6, domain, username, geo location, score as detailed vector of boolean values resulting on the following security checks)
        privacyPolicyD = "By reporting a detailed score, you agree to share the following information with EDAMAME:"
        privacyPolicyD += privacyHeader
        privacyPolicyD += "\n* Your score as a detailed vector of boolean values resulting on the following security checks:"
        
        # French version
        privacyPolicyDFR = "En rapportant un score détaillé, vous acceptez de partager les informations suivantes avec EDAMAME :"
        privacyPolicyDFR += privacyHeaderFR
        privacyPolicyDFR += "\n* Votre score sous forme d'un vecteur de valeurs booléennes résultant des tests de sécurité suivants :"
        
        for metric in model['metrics']:

            # Threat model
            threatHeader = "Threat"
            dimensionHeader = "Dimension"
            severityHeader = "Severity"
            tagsHeader = "Tags"
            implemationHeader = "Implementation"
            remedediationHeader= "Remediation"
            rollbackHeader= "Rollback"
            educationHeader = "Education"
            if loc == "FR":
                threatHeader = "Menace"
                severityHeader = "Sévérité"
                implemationHeader = "Implémentation"
                remedediationHeader = "Remédiation"
                rollbackHeader = "Retour en arrière"

            for localized in metric["description"]:
                if localized["locale"] == loc:
                    mdFile.new_header(level=1, title=localized['title'])
                    mdFile.new_header(level=2, title=threatHeader)
                    mdFile.new_paragraph(dimensionHeader + " : " + metric["dimension"] + " / " + severityHeader + " : " + str(metric["severity"]), bold_italics_code='b')
                    if len(metric["tags"]):
                        mdFile.new_paragraph(tagsHeader + " : " + ", ".join(metric["tags"]), bold_italics_code='i')
                    mdFile.new_paragraph(localized['summary'])

                    # Privacy policy
                    privacyPolicyD += "\n  * " + localized['title']
                    privacyPolicyDFR += "\n  * " + localized['title']

                    break

            mdFile.new_header(level=2, title=implemationHeader)
            print_action(loc, metric["implementation"]["elevation"], md_sanitize(metric["implementation"]["target"]), metric["implementation"]["system"], metric["implementation"]["minversion"])

            mdFile.new_header(level=2, title=remedediationHeader)
            if metric["remediation"]["target"] != "":
                print_action(loc, metric["remediation"]["elevation"], md_sanitize(metric["remediation"]["target"]), metric["remediation"]["system"], metric["remediation"]["minversion"])
            else:
                for localized in metric["remediation"]["education"]:
                    if localized["locale"] == loc:
                        mdFile.new_paragraph(md_sanitize(localized["target"]))
                        break

            mdFile.new_header(level=2, title=rollbackHeader)
            if metric["rollback"]["target"] != "":
                print_action(loc, metric["rollback"]["elevation"], md_sanitize(metric["rollback"]["target"]), metric["rollback"]["system"], metric["rollback"]["minversion"])
            else:
                for localized in metric["rollback"]["education"]:
                    if localized["locale"] == loc:
                        mdFile.new_paragraph(md_sanitize(localized["target"]))
                        break

        # Privacy policy

        privacyPolicyD += privacyTrailer
        privacyPolicyDFR += privacyTrailerFR

        if loc == "FR":
            mdFileP.new_paragraph(privacyPolicyFR)
            mdFilePD.new_paragraph(privacyPolicyDFR)
        else:
            mdFileP.new_paragraph(privacyPolicy)
            mdFilePD.new_paragraph(privacyPolicyD)

        mdFile.new_table_of_contents(table_title='Contents', depth=2)

        mdFile.create_md_file()
        mdFileP.create_md_file()
        mdFilePD.create_md_file()


