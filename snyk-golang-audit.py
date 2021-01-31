import click
import os
import sys
import json
import re
import requests
import semantic_version
import html

packages = []
json_response = []

def list_packages_golang(path_file):
    if not os.path.isfile(path_file):
        error = {"error": "file not exist or not accessible"}
        print("Error: {}".format(error['error']))
        sys.exit(1)
    # https://stackoverflow.com/questions/17039457/convert-first-column-of-data-from-text-file-into-a-list-in-python
    with open(path_file) as f:
        try:
            for line in f:
                spl = line.split()
                # Missing error handling, too tired today sorry
                package_go = {"package":"", "version":""}
                package_go['package'] = spl[0]
                version = spl[1][1:]
                version = version.split('/')[0]
                version = version.split('-')[0]
                version = version.split('+')[0]
                package_go['version'] = version
                packages.append(package_go)
        except:
            error = {"error": "empty file"}
            print("Error: {}".format(error['error']))
            sys.exit(1)

def snyk_audit_result(item_package, number, json_dict):
    package_name = requests.utils.quote(item_package['package'])
    r = requests.get('https://snyk.io/vuln/search/page/' + str(number) + '?type=golang&q=' + package_name)
    source_code = r.text
    source_code = source_code.replace("\n", "")
    if not r.ok:
        print("Error\nStatus code: {}".format(r.status_code))
        sys.exit(1)
    result = re.findall('No vulnerabilities were found when searching', source_code)
    if result:
        json_response.append({"package": item_package['package'], "version": item_package['version'], "result": {"vulnerable": False}})
        return False
    else:
        result = re.findall(r'<tr class="list-vulns__header">(.*?)<!-- .list-vulns -->', source_code)[0]
        vulnerability = re.findall(r'<strong >(.*?)</strong>', result)
        severity = re.findall(r'<span class="severity-list__item-text">(.*?)</span>', result)
        semversion = re.findall(r'<span  class="semver">(.*?)</span>', result)
        link = re.findall(r'</svg>                <a  href="(.*?)">', result)
        #published = re.findall(r'<td  class="l-align-right t--sm">(.*?)</td>', r.text).group(1)
        vulnerability_page = []
        for element in range(len(vulnerability)):
            if semversion[element] == '*' or semversion[element] == '':
                vulnerability_page.append({"type":vulnerability[element],"severity":severity[element],"semversion":semversion[element],"url":"https://snyk.io/vuln" + link[element]})
            else:
                vulnerable_versions = html.unescape(semversion[element]).split()
                for nversion in vulnerable_versions:
                    if semantic_version.Version(item_package['version']) in semantic_version.SimpleSpec(nversion):
                        vulnerability_page.append({"type": vulnerability[element], "severity": severity[element],
                                                   "semversion": html.unescape(semversion[element]), "url":"https://snyk.io/vuln" + link[element]})
        if vulnerability_page:
            last_package = json_response[len(json_response)-1]['package']
            if last_package != item_package['package']:
                json_response.append({"package": item_package['package'], "version": item_package['version'],
                                      "result": {"vulnerable": True, "vulnerabilities": []}})
            json_response[len(json_response)-1]['result']['vulnerabilities'] = json_response[len(json_response)-1]['result']['vulnerabilities'] + vulnerability_page
        result = re.findall(r'pagination__next', result)
        if not result:
            if json_response[len(json_response)-1]['package'] == item_package['package'] and json_dict == False:
                one_result = json_response[len(json_response) - 1]
                for element in one_result['result']['vulnerabilities']:
                    print("Vulnerable Package: {}".format(one_result['package']))
                    print("Vulnerability: {}".format(element['type']))
                    print("Severity: {}".format(element['severity']))
                    print("Version: {}".format(element['semversion']))
                    print("URL: {}\n".format(element['url']))
            return False
        else:
            return True


@click.command()
@click.argument('path')
@click.option('--json', 'json_dict', is_flag=True, help='Optional. Print JSON result.')
def snyk_audit(path, json_dict):
    """
    🧸 Snyk Golang audit\n
    https://github.com/luigigubello/snyk-golang-audit
    """
    list_packages_golang(path)
    packages_list = [dict(t) for t in {tuple(d.items()) for d in packages}]
    for item in packages_list:
        number = 1
        while snyk_audit_result(item, number, json_dict):
            number += 1
    if json_dict:
        print(json.dumps(json_response))

if __name__ == "__main__":
    snyk_audit()

