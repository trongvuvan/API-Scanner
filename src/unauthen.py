import requests
import mechanicalsoup
import requests
from bs4 import BeautifulSoup
from urllib.parse import parse_qsl, urljoin, urlparse
from urllib.parse import parse_qs
from collections import OrderedDict
from collections import Counter
import os
from urllib.parse import urlparse, urlunparse,urlencode,urljoin
import re
from collections import deque
from bs4 import BeautifulSoup
import requests
import requests.exceptions
from urllib.parse import urlsplit
from urllib.parse import urlparse
from collections import deque
import urllib3
urllib3.disable_warnings()

proxies = {
    "http" : "http://localhost:8080",
    "https" : "http://localhost:8080"
}
def get_base_domain(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc
def unau_crawl_page(url, base_domain):
    page_urls = set()
    try:
        response = requests.get(url,verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')

        for link in soup.find_all('a'):
            href = link.get('href')
            if href:
                full_url = urljoin(url, href)
                if get_base_domain(full_url) == base_domain:
                    print(full_url)
                    page_urls.add(full_url)

    except Exception as e:
        print("Error:", e)
    return page_urls
def un_crawl_all(start_url):
    base_domain = get_base_domain(start_url)
    visited_urls = set()

    visited_urls = unau_crawl_page(start_url, base_domain)

    while True:
        new_urls = set()

        for url in visited_urls:
            response = requests.get(url,verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            for link in soup.find_all('a'):
                href = link.get('href')
                if href:
                    full_url = urljoin(url, href)
                    if get_base_domain(full_url) == base_domain and full_url not in visited_urls:
                        print(full_url)
                        new_urls.add(full_url)

        if not new_urls:
            break
        visited_urls.update(new_urls)
    return visited_urls
def extract_form_parameters(url):
    response = requests.get(url,verify=False)
    soup = BeautifulSoup(response.text, 'html.parser')
    parameters = {}
    newurl = ''
    try : 
        form = soup.find('form',method='GET')
        if form is None :
            form = soup.find('form',method='get')
        action = form.get('action')
        method = form.get('method', 'GET')
        inputs = form.find_all(['input', 'select','textarea'])

        for input_tag in inputs:
            name = input_tag.get('name')
            value = input_tag.get('value', '')

            if name:
                parameters[name] = value
    except:
        print("no parameter get")
    for param in parameters:
        if method == 'GET':
            temp = requests.get(url,params=parameters,verify=False)
            newurl = temp.url
    print('params',parameters)
    print('new :',newurl)
    return parameters

def extract_post_parameters(url):
    response = requests.get(url,verify=False)
    print(response.url)
    parameters = {}
    urlcontain = ''
    soup = BeautifulSoup(response.text, 'html.parser')
    try :
        forms = soup.find_all('form', method='POST')
        if len(forms) == 0:
            forms = soup.find_all('form', method='post')
        for form in forms:
            method = form.get('method', 'post')
            inputs = form.find_all(['input', 'select','textarea'])
            for input_tag in inputs:
                if input_tag.name == 'input':
                    name = input_tag.get('name')
                    value = input_tag.get('value', '')
                    if name and name not in parameters:
                        parameters[name] = value
                elif input_tag.name == 'textarea':
                    name = input_tag.get('name')
                    value = input_tag.get('value', '')
                    if name and name not in parameters:
                        parameters[name] = value
                elif input_tag.name == 'select':
                    name = input_tag.get('name')
                    selected_option = input_tag.find('option', selected=True)
                    value = selected_option.get('value', '') if selected_option else ''
                    if name and name not in parameters:
                        parameters[name] = value
    except:
        print("not post")
    if parameters:
        if method == 'POST':       
            postdata = requests.post(url, params=parameters,verify=False)
            print('POST :',postdata.url)
            urlcontain = postdata.url
    return parameters   
class UnauthenScanHeaders:
    def __init__(self, url):
        self.url = url
        response = requests.get(self.url)
        self.headers = response.headers
        self.cookies = response.cookies
    def scan_xxss(self):
        """config failure if X-XSS-Protection header is not present"""
        try:
            if self.headers["X-XSS-Protection"]:
                print("[+]", "X-XSS-Protection", ':', "pass")
                check = False
                return check
        except KeyError:
            print("[-]", "X-XSS-Protection header not present", ':', "fail!")
            check = True
            return check
    def scan_nosniff(self):
        """X-Content-Type-Options should be set to 'nosniff' """
        try:
            if self.headers["X-Content-Type-Options"].lower() == "nosniff":
                print("[+]", "X-Content-Type-Options", ':', "pass")
                check = False
                return check
            else:
                print("[-]", "X-Content-Type-Options header not set correctly", ':', "fail!")
                check = True
                return check
        except KeyError:
            print("[-]", "X-Content-Type-Options header not present", ':', "fail!")
    def scan_xframe(self):
        """X-Frame-Options should be set to DENY or SAMEORIGIN"""
        try:
            if "deny" in self.headers["X-Frame-Options"].lower():
                print("[+]", "X-Frame-Options", ':', "pass")
                check = False
                return check
            elif "sameorigin" in self.headers["X-Frame-Options"].lower():
                print("[+]", "X-Frame-Options", ':', "pass")
                check = False
                return check
            else:
                print("[-]", "X-Frame-Options header not set correctly", ':', "fail!")
                check = True
                return check
        except KeyError:
            print("[-]", "X-Frame-Options header not present", ':', "fail!")
            check = True
            return check
            
    def scan_hsts(self):
        """config failure if HSTS header is not present"""
        try:
            if self.headers["Strict-Transport-Security"]:
                print("[+]", "Strict-Transport-Security", ':', "pass")
                check = False
                return check
        except KeyError:
            print("[-]", "Strict-Transport-Security header not present", ':', "fail!")
            check = True
            return check
    
    def scan_policy(self):
        """config failure if Security Policy header is not present"""
        try:
            if self.headers["Content-Security-Policy"]:
                print("[+]", "Content-Security-Policy", ':', "pass")
                check = False
                return check
        except KeyError:
            print("[-]", "Content-Security-Policy header not present", ':', "fail!")
            check = True
            return check
    def scan_cors(self):
        try:
            if self.headers["Access-Control-Allow-Origin"]:
                cors_origin = self.headers["Access-Control-Allow-Origin"]
                if cors_origin == '*':
                    print("Potentially unsafe 'Access-Control-Allow-Origin' header found:", cors_origin)
                    check = True
                    return check
                else:
                    print("'Access-Control-Allow-Origin' header:", cors_origin)
                    check = False
                    return check
        except KeyError:
            print("[-]", "Access-Control-Allow-Origin' header not found", ':', "fail!")
            check = False
            return check
    def scan_server(self):
        try:
            if self.headers["Server"] or self.headers["X-Powered-By"]:
                if self.headers["X-Powered-By"]:
                    server_info = self.headers['X-Powered-By']
                else:
                    server_info = self.headers['Server']
                print("Server information:", server_info)
                check = True
                return check
            else:
                print("Server information not found")
                check = False
                return check
        except KeyError:
            print("[-]", "Access-Control-Allow-Origin' header not found", ':', "fail!")
            check = False
            return check    
    def scan_secure(self, cookie):
        """Set-Cookie header should have the secure attribute set"""
        if cookie.secure:
            print("[+]", "Secure", ':', "pass")
            check = False
            return check
        else:
            print("[-]", "Secure attribute not set", ':', "fail!")
            check = True
            return check
    def scan_httponly(self, cookie):
        """Set-Cookie header should have the HttpOnly attribute set"""
        if cookie.has_nonstandard_attr('httponly') or cookie.has_nonstandard_attr('HttpOnly'):
            print("[+]", "HttpOnly", ':', "pass")
            check = False
            return check
        else:
            print("[-]", "HttpOnly attribute not set", ':', "fail!")
            check = True
            return check
def unau_sql_scan(scanurl):
    get_data = extract_form_parameters(scanurl)
    post_data = extract_post_parameters(scanurl)
    
    print('post',post_data)
    print('get',get_data)
    if post_data:
        print('POST----------------------------------------------------------------')
        injects = []
        for data in post_data:
            if post_data[data] == '':
                post_data[data] = '1' 
                injects.append(data)
        temp = requests.post(scanurl,params = post_data,verify=False)
        payurl = temp.url
        filepath = './src/payload/sqltime.txt'
        print('current payload',post_data)
        with open(filepath) as fp:
            line = fp.readline()
            while line:
                combined = line.strip()
                for inject in injects:
                    for data in post_data:
                        if inject == data:
                            post_data[data] = '1'
                for data in post_data:
                    if post_data[data] == '1':
                        post_data[data] = '1'+combined
                        print(post_data)
                        rs = requests.post(payurl,params = post_data,verify=False)
                        print('total : ',rs.elapsed.total_seconds())
                        if rs.elapsed.total_seconds() > 20:
                            print('TING TING : SQL FOUND')
                            check = True
                            return True
                        else: 
                            print('TING TING : NOT FOUND')
                            check = False   
                line = fp.readline()
    if get_data:
        print('GET----------------------------------------------------------------')
        for data in get_data:
            if get_data[data] == '':
                get_data[data] = '1'
        temp = requests.get(scanurl,params = get_data,verify=False)
        payurl = temp.url
        filepath = './src/payload/sqltime.txt'
        print('current payload',get_data)
        with open(filepath) as fp:
            line = fp.readline()
            while line:
                combined = line.strip()
                for data in get_data:
                    if data != 'Submit' or data != 'Login':
                        get_data[data] = '1'+combined
                        print(get_data)
                        rs = requests.get(payurl,params = get_data,verify=False)
                        print('total : ',rs.elapsed.total_seconds())
                        if rs.elapsed.total_seconds() > 20:
                            print('TING TING : SQL FOUND')
                            return True
                        else: 
                            print('TING TING : NOT FOUND')
                            check = False           
                line = fp.readline()
    else:
        return 

def unau_path_travel_scan(scanurl):
    parsed_url = urlparse(scanurl)
    query_params = parse_qs(parsed_url.query)
    print(query_params)
    filepath = './src/payload/rfi.txt'
    linux_file_paths = [
        "/etc/passwd",
        "/etc/hosts","/etc/passwd%00",
        "/etc/hosts%00",
        "/etc/passwd%00.jpg",
        "/etc/hosts%00.jpg",
        
    ]

    windows_file_paths = [
        "C:\\Windows\\win.ini",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\win.ini%00",
        "C:\\Windows\\System32\\drivers\\etc\\hosts%00",
        "C:\\Windows\\win.ini%00.jpg",
        "C:\\Windows\\System32\\drivers\\etc\\hosts%00.jpg",
    ]
    with open(filepath) as fp:
        line = fp.readline()
        while line:
            combined = line.strip()
            for param in query_params:
                if param != 'Submit' or param != 'Confirm':
                    for linux in linux_file_paths:
                        query_params[param] = combined + linux
                        updated_query = urlencode(query_params, doseq=True)
                        new_url_parts = list(parsed_url)
                        new_url_parts[4] = updated_query
                        new_url = urlunparse(new_url_parts)
                        print(new_url)
                        rs = requests.get(new_url,verify=False)
                        if "root:" in rs.text:
                            print('FOUND RFI in payload',query_params[param])
                            return True
                        else:
                            print('NOT FOUND RFI')
                    for window in windows_file_paths:
                        query_params[param] = combined + linux
                        updated_query = urlencode(query_params, doseq=True)
                        new_url_parts = list(parsed_url)
                        new_url_parts[4] = updated_query
                        new_url = urlunparse(new_url_parts)
                        print(new_url)
                        rs = requests.get(new_url,verify=False)
                        print(query_params)
                        if "Windows" in rs.text:
                            print('FOUND RFI in payload',query_params[param])
                            return True
                        else:
                            print('NOT FOUND RFI')
            line = fp.readline()
    print(query_params)
def unau_rxss_scan(scanurl):
    get_data = extract_form_parameters(scanurl)
    post_data = extract_post_parameters(scanurl)
    
    print('post',post_data)
    print('get',get_data)
    if post_data:
        print('POST----------------------------------------------------------------')
        injects = []
        for data in post_data:
            if post_data[data] == '':
                post_data[data] = '1' 
                injects.append(data)
        temp = requests.post(scanurl,params = post_data,verify=False)
        payurl = temp.url
        filepath = './src/payload/xss.txt'
        print('current payload',post_data)
        with open(filepath) as fp:
            line = fp.readline()
            while line:
                combined = line.strip()
                for inject in injects:
                    for data in post_data:
                        if inject == data:
                            post_data[data] = '1'
                for data in post_data:
                    if post_data[data] == '1':
                        post_data[data] = '1'+combined
                    print(post_data)
                    check = True
                    rs = requests.post(payurl,params = post_data,verify=False)
                    if re.search(re.escape(combined), rs.text, re.IGNORECASE):
                        print('Potential Reflective XSS found:')
                        print('Payload:', combined)
                        print('Response:', rs.text)
                        print()
                        print('TING TING : XSS FOUND')
                        check = True
                        return True
                    else: 
                        print('TING TING : NOT FOUND')
                        check = False   
                line = fp.readline()
    if get_data:
        print('GET----------------------------------------------------------------')
        for data in get_data:
            if get_data[data] == '':
                get_data[data] = '1'
        temp = requests.get(scanurl,params = get_data,verify=False)
        payurl = temp.url
        filepath = './src/payload/xss.txt'
        print('current payload',get_data)
        with open(filepath) as fp:
            line = fp.readline()
            while line:
                combined = line.strip()
                for data in get_data:
                    if data != 'Submit' or data != 'Login' or data != 'Confirm':
                        get_data[data] = combined
                        print(get_data)
                        check = True
                        rs = requests.get(scanurl,params = get_data,verify=False)
                        print(rs.url)
                        print(get_data)  
                        if re.search(re.escape(combined), rs.text, re.IGNORECASE):
                            print('TING TING : XSS FOUND')
                            check = True
                            return True
                        else: 
                            print('TING TING : NOT FOUND')
                            check = False       
                line = fp.readline()
    else:
        return 


