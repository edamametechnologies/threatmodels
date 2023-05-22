from mdutils.mdutils import MdUtils
import json


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

sources = ['Windows', 'macOS', 'iOS']
for source in sources:
    for loc in ("EN", "FR"):
        mdFile = MdUtils(file_name='../threatmodels.wiki/threatmodel-' + source + '-' + loc, title=source + ' Threat Model ' + '('+ loc + ')')

        with open('threatmodel-' + source + '.json', 'r') as json_file:
            model = json.load(json_file)

        for metric in model['metrics']:

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
                    break

            mdFile.new_header(level=2, title=implemationHeader)
            print_action(loc, metric["implementation"]["elevation"], metric["implementation"]["target"], metric["implementation"]["system"], metric["implementation"]["minversion"])

            mdFile.new_header(level=2, title=rollbackHeader)
            if metric["remediation"]["target"] != "":
                print_action(loc, metric["remediation"]["elevation"], metric["remediation"]["target"], metric["remediation"]["system"], metric["remediation"]["minversion"])
            else:
                for localized in metric["remediation"]["education"]:
                    if localized["locale"] == loc:
                        mdFile.new_paragraph(localized["target"])
                        break

            mdFile.new_header(level=2, title=remedediationHeader)
            if metric["rollback"]["target"] != "":
                print_action(loc, metric["rollback"]["elevation"], metric["rollback"]["target"], metric["rollback"]["system"], metric["rollback"]["minversion"])
            else:
                for localized in metric["rollback"]["education"]:
                    if localized["locale"] == loc:
                        mdFile.new_paragraph(localized["target"])
                        break

        mdFile.new_table_of_contents(table_title='Contents', depth=2)

        mdFile.create_md_file()


