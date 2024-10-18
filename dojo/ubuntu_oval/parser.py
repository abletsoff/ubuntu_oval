import hashlib
import json
from urllib.parse import urlparse
from dojo.models import Endpoint, Finding


class UbuntuOVALParser(object):
    """
    Ubuntu Oval
    """

    def get_scan_types(self):
        return ["Ubuntu OVAL"]

    def get_label_for_scan_types(self, scan_type):
        return "Ubuntu OVAL"

    def get_description_for_scan_types(self, scan_type):
        return "Ubuntu OVAL file can be imported in JSON format (option --json)."

    def get_findings(self, file, test):
        #severities_scores = {'Info': 0, 'Low':1, 'Medium': 2, 'High': 3, 'Critical' :4}
        #severity = 'info'
        dupes = dict()
        print('!Hello worlds:)')
        full_tree = json.load(file)
        for tree in full_tree:
            #severities_scores = {'Info': 0, 'Low':1, 'Medium': 2, 'High': 3, 'Critical' :4}
            #severity = 'Info'
            dupes = dict()
            full_tree = json.load(file)
            for tree in full_tree:
                customer = tree['customer']
                server_type = tree['server_type']
                descriptions = []

                for node in tree['findings']:
                    descriptions.append(node['title'])
                    for reference in node['references'][:3]:
                        descriptions.append(f" - {reference['ref_url']}")

         #       for node in tree['findings']:
         #           vuln_severity = node['severity'].capitalize()
         #           print(vuln_severity)
         #           if vuln_severity == 'Negligible':
         #               vuln_severity = 'Info'
         #           elif vuln_severity == 'None':
         #               vuln_severity = 'Info'
         #           if severities_scores[vuln_severity] > severities_scores[severity]:
         #               severity = vuln_severity

         #   finding.severity = severity
            finding.severity = 'High'
            findings_count = len(descriptions) 
            finding = Finding(test=test)
            title = f"{customer}_{server_type}_{findings_count}-vulnerabilites"
            finding.title = title
            
            str_description = "\n".join(descriptions)
            finding.description = str_description
            finding.component_name = "Ubuntu OS"
            finding.cwe=1395
            finding.vuln_id_from_tool = hashlib.sha256(str_description.encode('utf-8')).hexdigest()
            finding.url = f'{customer}_{server_type}' 
            finding.unsaved_endpoints = list()

            # internal de-duplication
            dupe_key = hashlib.sha256(str(finding.title + finding.vuln_id_from_tool).encode('utf-8')).hexdigest()

            if dupe_key in dupes:
                find = dupes[dupe_key]
                if finding.description:
                    find.description += "\n" + finding.description
                find.unsaved_endpoints.extend(finding.unsaved_endpoints)
                dupes[dupe_key] = find
            else:
                dupes[dupe_key] = finding

        return list(dupes.values())

    def convert_severity(self, num_severity):
        """Convert severity value"""
        if num_severity >= -10:
            return "Low"
        elif -11 >= num_severity > -26:
            return "Medium"
        elif num_severity <= -26:
            return "High"
        else:
            return "Info"
