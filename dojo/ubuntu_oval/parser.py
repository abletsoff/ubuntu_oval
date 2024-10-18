import hashlib
import json
from urllib.parse import urlparse
from dojo.models import Endpoint, Finding


class UbuntuOVALParser(object):
    """
    UbuntuOVAL
    """

    def get_scan_types(self):
        return ["Ubuntu OVAL"]

    def get_label_for_scan_types(self, scan_type):
        return "Ubunut OVAL"

    def get_description_for_scan_types(self, scan_type):
        return "Ubuntu OVAL"

    def get_findings(self, file, test):
        dupes = dict()
        tree = json.load(file)
        for branch in tree:
            finding = Finding(test=test)
            count = 0 # Vulnerabilites count
            descriptions = []
            severities_scores = {'Info': 0, 'Low':1, 'Medium': 2, 'High': 3, 'Critical' :4}
            severity = 'Info'

            for node in branch['findings']:
                descriptions.append(node['title'])
                count = count + 1
                for reference in node['references'][:3]:
                    descriptions.append(f" - {reference['ref_url']}")
            
            for node in branch['findings']:
                vuln_severity = node['severity'].capitalize()
                if vuln_severity == 'Negligible':
                    vuln_severity = 'Info'
                elif vuln_severity == 'None':
                    vuln_severity = 'Info'
                if severities_scores[vuln_severity] > severities_scores[severity]:
                    severity = vuln_severity

            finding.severity = severity
            customer = branch['customer']
            server_type = branch['server_type']
            finding.title = f"{customer}_{server_type}_{count}-vulnerabilites"
            finding.description = "\n".join(descriptions)
            finding.component_name = "Ubuntu OS"
            finding.cwe=1395
            finding.vuln_id_from_tool = hashlib.sha256(finding.description.encode('utf-8')).hexdigest()
            finding.unsaved_endpoints = list()

            print(f'{customer} {server_type} {finding.title}')
            dupe_key = hashlib.sha256(str(finding.title).encode('utf-8')).hexdigest()

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

