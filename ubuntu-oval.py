#!/usr/bin/python3

import xml.etree.ElementTree as ET
import json
import sys
import argparse
import requests
import bz2
import datetime
import os

server_type = ''
customer = ''

def download_oval(release):
    url = f'https://security-metadata.canonical.com/oval/com.ubuntu.{release}.usn.oval.xml.bz2'
    archive_filename = f'/tmp/com.ubuntu.{release}.usn.oval.xml.bz2'
    filename = f'/tmp/com.ubuntu.{release}.usn.oval.xml'
    
    # Check if file has been already downlaoded
    if os.path.exists(filename):
        mod_time = os.path.getmtime(filename)
        mod_time = datetime.datetime.fromtimestamp(mod_time)
        time_diff = datetime.datetime.now() - mod_time

        if time_diff < datetime.timedelta(hours=12):
            return

    # Download oval
    with requests.get(url, stream=True) as response:
        response.raise_for_status()
        with open(archive_filename, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
    # Decompress archive
    with bz2.BZ2File(archive_filename, 'rb') as file, open(filename, 'wb') as out_file:
        out_file.write(file.read())

def get_findings(filename):
    global server_type
    global customer
    findings = []
    # Solve those '\n' symbols troubles
    with open(filename, 'r') as f:
        for line in f.readlines():
            if line == 'Evaluation done.\n':
                continue
            if 'Server: ' in line:
                server_type = line.split(' ')[1][:-1]
                continue
                
            if 'Customer: ' in line:
                customer = line.split(' ')[1][:-1]
                continue

            definition = line.split(' ')

            definition_id = definition[1][:-1]
            definition_state = definition[2]
            if definition_state == 'true\n':
                findings.append(definition_id)
    return findings


def get_definitions(filename):
    namespaces = {
        'oval-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5'
    }
    definitions = []
    tree = ET.parse(filename)
    root = tree.getroot()
    xml_definitions = root.findall('.//oval-def:definition', namespaces)

    for xml_definition in xml_definitions:
        id = xml_id = xml_definition.get('id')
        title = xml_title = xml_definition.find('.//oval-def:title', namespaces).text

        references = []
        xml_references = xml_definition.findall('.//oval-def:reference', namespaces)
        reference_count = 0 # Limit amount
        for xml_reference in xml_references:
            reference = {}
            reference['source'] = xml_reference.get('source')
            reference['ref_id'] = xml_reference.get('ref_id')
            reference['ref_url'] = xml_reference.get('ref_url')
            if reference_count < 3:
                reference_count = reference_count + 1
                references.append(reference)
            else:
                break

        xml_advisory = xml_definition.find('.//oval-def:advisory', namespaces)
        if xml_advisory:
            xml_severity = xml_advisory.find('.//oval-def:severity', namespaces)
            severity = xml_severity.text
        else:
            severity = 'low'
      
        definition = {} 
        definition['id'] = id
        definition['title'] = title
        definition['references'] = references
        definition['severity'] = severity
        definitions.append(definition)

    return definitions

def construct_report(definitions, findings):
    results = []
    for definition in definitions:
        for finding in findings:
            if definition['id'] == finding:
                results.append(definition)
    report = {}
    report['customer'] = customer
    report['server_type'] = server_type
    report['findings'] = results
    if len(results) != 0:
        print(json.dumps(report))

def arguments_parse():
    parser = argparse.ArgumentParser(description="Ubuntu OVAL report generation")
    parser.add_argument('--release', type=str, required=True, help='Ubuntu release (e.g. focal, xenial, ...)')
    parser.add_argument('--report', type=str, required=True, help='Report from OpenSCAP')
    return parser.parse_args()

args = arguments_parse()
download_oval(args.release)
definitions = get_definitions(f'/tmp/com.ubuntu.{args.release}.usn.oval.xml')
findings = get_findings(args.report)
construct_report(definitions, findings)
