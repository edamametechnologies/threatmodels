from mdutils.mdutils import MdUtils
import json


def print_action(loc, elevation, target):

    actionHeader = "Action"
    elevationHeader = "Elevation"
    targetHeader = "Script"
    action = "Command line"
    if loc == "FR":
        action = "Ligne de commande"

    mdFile.new_line()
    mdFile.new_table(columns=3, rows=2, text=[actionHeader, elevationHeader, targetHeader, action, elevation, target], text_align='left')

source = 'threatmodel-macOS.json'
for loc in ("EN", "FR"):
    mdFile = MdUtils(file_name='../threatmodels.wiki/threatmodel-macOS-' + loc, title='macOS Threat Model ' + '('+ loc + ')')

    with open(source, 'r') as json_file:
        model = json.load(json_file)

    for metric in model['metrics']:

        threatHeader = "Threat"
        dimensionHeader = "Dimension"
        tagsHeader = "Tags"
        implemationHeader = "Implementation"
        remedediationHeader= "Remediation"
        rollbackHeader= "Rollback"
        educationHeader = "Education"
        if loc == "FR":
            threatHeader = "Menace"
            implemationHeader = "Implémentation"
            remedediationHeader = "Remédiation"
            rollbackHeader = "Retour en arrière"

        for localized in metric["description"]:
            if localized["locale"] == loc:
                mdFile.new_header(level=1, title=localized['title'])
                mdFile.new_header(level=2, title=threatHeader)
                mdFile.new_paragraph(dimensionHeader + " : " + metric["dimension"], bold_italics_code='b')
                if len(metric["tags"]):
                    mdFile.new_paragraph(tagsHeader + " : " + ", ".join(metric["tags"]), bold_italics_code='i')
                mdFile.new_paragraph(localized['summary'])
                break

        mdFile.new_header(level=2, title=implemationHeader)
        print_action(loc, metric["implementation"]["elevation"], metric["implementation"]["target"])

        mdFile.new_header(level=2, title=rollbackHeader)
        if metric["remediation"]["target"] != "":
            print_action(loc, metric["remediation"]["elevation"], metric["remediation"]["target"])
        else:
            for localized in metric["remediation"]["education"]:
                if localized["locale"] == loc:
                    mdFile.new_paragraph(localized["target"])
                    break

        mdFile.new_header(level=2, title=remedediationHeader)
        if metric["rollback"]["target"] != "":
            print_action(loc, metric["rollback"]["elevation"], metric["rollback"]["target"])
        else:
            for localized in metric["rollback"]["education"]:
                if localized["locale"] == loc:
                    mdFile.new_paragraph(localized["target"])
                    break

    mdFile.new_table_of_contents(table_title='Contents', depth=2)

    mdFile.create_md_file()

