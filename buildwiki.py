from mdutils.mdutils import MdUtils
import json

source = 'threatmodel-macOS.json'
for loc in ("EN", "FR"):
    mdFile = MdUtils(file_name='../threatmodels.wiki/threatmodel-macOS-' + loc, title='macOS Threat Model ' + '('+ loc + ')')

    with open(source, 'r') as json_file:
        model = json.load(json_file)

    for metric in model['metrics']:

        threat = "Threat"
        dim = "Dimension"
        tags = "Tags"
        impl = "Implementation"
        remed = "Remediation"
        roll = "Rollback"
        educ = "Education"
        cli = "Command line"
        elev = "elevation"
        if loc == "FR":
            threat = "Menace"
            imp = "Implémentation"
            remed = "Remédiation"
            roll = "Retour en arrière"
            cli = "Ligne de commande"

        for localized in metric["description"]:
            if localized["locale"] == loc:
                mdFile.new_header(level=1, title=localized['title'])
                mdFile.new_header(level=2, title=threat)
                mdFile.new_paragraph(localized['summary'])
                break

        mdFile.new_paragraph(dim + " : " + metric["dimension"], bold_italics_code='b')
        if len(metric["tags"]):
            mdFile.new_paragraph(tags + " : " + ", ".join(metric["tags"]), bold_italics_code='i')

        mdFile.new_header(level=2, title=impl)
        mdFile.new_paragraph(cli + " ( " + elev + " " + metric["implementation"]["elevation"] + " ) : " + metric["implementation"]["target"])

        mdFile.new_header(level=2, title=remed)
        if metric["remediation"]["target"] != "":
            mdFile.new_paragraph(cli + " ( " + elev + " " + metric["remediation"]["elevation"] + " ) : " + metric["remediation"]["target"])
        else:
            for localized in metric["remediation"]["education"]:
                if localized["locale"] == loc:
                    mdFile.new_paragraph(localized["target"])
                    break

        mdFile.new_header(level=2, title=roll)
        if metric["rollback"]["target"] != "":
            mdFile.new_paragraph(cli + " ( " + elev + " " + metric["rollback"]["elevation"] + " ) : " + metric["rollback"]["target"])
        else:
            for localized in metric["rollback"]["education"]:
                if localized["locale"] == loc:
                    mdFile.new_paragraph(localized["target"])
                    break

    mdFile.new_table_of_contents(table_title='Contents', depth=2)

    mdFile.create_md_file()

