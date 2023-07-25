import mechanicalsoup
import requests
from bs4 import BeautifulSoup
from urllib.parse import parse_qs
from collections import OrderedDict
from collections import Counter
import os
from urllib.parse import urlparse, urlunparse,urlencode,urljoin
import re
proxies = {
    'http':'http://127.0.0.1:8080',
    'https':'https://127.0.0.1:8080'
}
def get_session(loginurl,userparam,passparam,csrfparam,username,password):
    # Set up a session
    login_data = {
        userparam: username,
        passparam: password,
    }
    session = requests.Session()

    # Send a GET request to retrieve the login page
    response = session.get(loginurl,verify=False)
    soup = BeautifulSoup(response.text, 'html.parser')
    button_element = soup.find('button')
    if button_element:
    # Get the name and value attributes of the button
        if button_element.get('name'):
            button_name = button_element.get('name')
            if button_element.get('value'):
                button_value = button_element.get('value')
                login_data[button_name] = button_value
    # Extract the CSRF token from the login form\
    loginname = ''
    loginvalue = ''
    csrf_token = ''
    try :
        csrf_token = soup.find('input', {'name': csrfparam}).get('value')
        login_data[csrfparam] = csrf_token
    except :
        print("nothings")
    try :
        loginvalue = soup.find('input', {'type': 'submit'}).get('value')
        loginname = soup.find('input', {'type': 'submit'}).get('name')
        login_data[loginname] = loginvalue
    except:
        print("nothings")
        # Send a POST request to the login page with the login data
    response = session.post(loginurl, data=login_data,verify=False)
    # Check if the login was successful by analyzing the response

    return session
def extract_form_parameters(url,loginurl,userparam,passparam,csrfparam,username,password):

    session = get_session(loginurl,userparam,passparam,csrfparam,username,password)
    response = session.get(url,verify=False)
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
            temp = session.get(url,params=parameters,verify=False)
            newurl = temp.url
    print('params',parameters)
    print('new :',newurl)
    return parameters
def extract_post_parameters(url,loginurl,userparam,passparam,csrfparam,username,password):
    session = get_session(loginurl,userparam,passparam,csrfparam,username,password)
    response = session.get(url,verify=False)
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
            postdata = session.post(url, params=parameters,verify=False)
            print('POST :',postdata.url)
            urlcontain = postdata.url
    return parameters
 
def sql_scan(scanurl,loginurl,userparam,passparam,csrfparam,username,password):
    session = get_session(loginurl,userparam,passparam,csrfparam,username,password)
   
    get_data = extract_form_parameters(scanurl,loginurl,userparam,passparam,csrfparam,username,password)
    post_data = extract_post_parameters(scanurl,loginurl,userparam,passparam,csrfparam,username,password)
    
    print('post',post_data)
    print('get',get_data)
    if post_data:
        print('POST----------------------------------------------------------------')
        injects = []
        for data in post_data:
            if post_data[data] == '':
                post_data[data] = '1' 
                injects.append(data)
        temp = session.post(scanurl,params = post_data,verify=False)
        payurl = temp.url
        filepath = './src/payload/sqli.txt'
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
                        rs = session.post(payurl,params = post_data,verify=False)
                        print('total : ',rs.elapsed.total_seconds())
                        if rs.elapsed.total_seconds() > 5:
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
        temp = session.get(scanurl,params = get_data,verify=False)
        payurl = temp.url
        filepath = './src/payload/sqli.txt'
        print('current payload',get_data)
        with open(filepath) as fp:
            line = fp.readline()
            while line:
                combined = line.strip()
                for data in get_data:
                    if data != 'Submit' or data != 'Login':
                        get_data[data] = '1'+combined
                        print(get_data)
                        rs = session.get(payurl,params = get_data,verify=False)
                        print('total : ',rs.elapsed.total_seconds())
                        if rs.elapsed.total_seconds() > 5:
                            print('TING TING : SQL FOUND')
                            return True
                        else: 
                            print('TING TING : NOT FOUND')
                            check = False           
                line = fp.readline()
    else:
        return 

def path_travel_scan(scanurl,loginurl,userparam,passparam,csrfparam,username,password):
    session = get_session(loginurl,userparam,passparam,csrfparam,username,password)
    parsed_url = urlparse(scanurl)
    query_params = parse_qs(parsed_url.query)
    print(query_params)
    filepath = './src/payload/rfi.txt'
    linux_file_paths = [
        "/etc/passwd",
        "/etc/hosts",
        "/var/log/apache/access.log",
    ]

    windows_file_paths = [
        "C:\\Windows\\win.ini",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\xampp\\apache\\logs\\access.log",
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
                        rs = session.get(new_url,verify=False)
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
                        rs = session.get(new_url,verify=False)
                        print(query_params)
                        if "Windows" in rs.text:
                            print('FOUND RFI in payload',query_params[param])
                            return True
                        else:
                            print('NOT FOUND RFI')
            line = fp.readline()
    print(query_params)
def rxss_scan(scanurl,loginurl,userparam,passparam,csrfparam,username,password):
    session = get_session(loginurl,userparam,passparam,csrfparam,username,password)
   
    get_data = extract_form_parameters(scanurl,loginurl,userparam,passparam,csrfparam,username,password)
    post_data = extract_post_parameters(scanurl,loginurl,userparam,passparam,csrfparam,username,password)
    
    print('post',post_data)
    print('get',get_data)
    if post_data:
        print('POST----------------------------------------------------------------')
        injects = []
        for data in post_data:
            if post_data[data] == '':
                post_data[data] = '1' 
                injects.append(data)
        temp = session.post(scanurl,params = post_data,verify=False)
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
                    rs = session.post(payurl,params = post_data,verify=False)
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
        temp = session.get(scanurl,params = get_data,verify=False)
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
                        rs = session.get(scanurl,params = get_data,verify=False)
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
    
    
def check_url_valid(url):
    req = requests.get(url)
    if req.status_code == 404:
        return False
    else :
        return True
# def dxss_scan(scanurl,loginurl,userparam,passparam,csrfparam,username,password):
#     session = get_session(loginurl,userparam,passparam,csrfparam,username,password)
#     response = session.get(scanurl)
#     get_data = extract_form_parameters(scanurl,loginurl,userparam,passparam,csrfparam,username,password)
#     post_data = extract_post_parameters(scanurl,loginurl,userparam,passparam,csrfparam,username,password)
#     # Parse the HTML content using BeautifulSoup
#     soup = BeautifulSoup(response.content, 'html.parser')
#     user_elements = soup.find_all(['input', 'textarea', 'select'])

#     # Scan each user-controlled element for potential XSS payloads
#     for element in user_elements:
#         # Get the value of the element
#         value = element.get('value')

#         # Check if the value contains a potential XSS payload
#         if value and re.search(r'<script\b[^>]*>', value):
#             print('Potential DOM-based XSS found:')
#             print('Element:', element)
#             print('Value:', value)
#             print()

# scanurl = 'http://127.0.0.1:3456/vulnerabilities/xss_d/'
# loginurl = 'http://127.0.0.1:3456/login.php'
# username = 'admin' 
# password = ''
# userparam = 'username'
# passparam = 'password'
# csrfparam = 'user_token'

# a = dxss_scan(scanurl,loginurl,userparam,passparam,csrfparam,username,password)
# print(a)