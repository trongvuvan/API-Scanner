import mechanicalsoup
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from urllib.parse import parse_qs
from collections import OrderedDict
from collections import Counter
import os
from urllib.parse import urljoin
from urllib.parse import urlparse, urlunparse
proxies = {
    "http" : "http://localhost:8080",
    "https" : "http://localhost:8080"
}
headers = {"Cache-Control": "max-age=0", "sec-ch-ua": "\"Not:A-Brand\";v=\"99\", \"Chromium\";v=\"112\"", "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": "\"Windows\"", "Upgrade-Insecure-Requests": "1", "Origin": "http://127.0.0.1:3456", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.138 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Referer": "http://127.0.0.1:3456/login.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
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
def is_link(string):
    parsed = urlparse(string)
    return bool(parsed.scheme and parsed.netloc)
def escape_traversal_path(string):
    return os.path.normpath(string)
def replace_backslashes(string):
    return string.replace('\\', '/')
def replace_double_slashes(string):
    return string.replace('//', '/')
def add_trailing_slash(url):
    if not url.endswith('/'):
        url += '/'
    return url

def escape_double_slash(url):
    parsed_url = urlparse(url)
    path = parsed_url.path.rstrip('/')  # Remove trailing slash from the path
    escaped_path = path.replace('//', '/')  # Replace double slashes with a single slash
    parsed_url = parsed_url._replace(path=escaped_path)
    return urlunparse(parsed_url)

def crawl(url,loginurl,userparam,passparam,csrfparam,username,password):
    # Send a GET request to the specified URL
    session = get_session(loginurl,userparam,passparam,csrfparam,username,password)
    response = session.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')

    # Find all anchor elements
    anchor_tags = soup.find_all('a')

    href_list = []
    # Extract the href attribute from each anchor element
    for anchor in anchor_tags:
        href = anchor.get('href')
        if href:
            if is_link(href):
                print("is a link")
            else:
                newurl = add_trailing_slash(url) + replace_double_slashes(replace_backslashes(escape_traversal_path(href)))
                brand = session.get(escape_double_slash(newurl))
                href_list.append(brand.url)
                print("format : ",newurl)
    print(href_list)
    return href_list
def get_base_url(url):
    parsed_url = urlparse(url)
    base_url = urlunparse((parsed_url.scheme, parsed_url.netloc,'','', '', ''))
    return base_url
def extract_form_parameters(url,loginurl,userparam,passparam,csrfparam,username,password):

    session = get_session(loginurl,userparam,passparam,csrfparam,username,password)
    response = session.get(url,verify=False)
    soup = BeautifulSoup(response.text, 'html.parser')
    parameters = {}
    newurl = ''
    try : 
        form = soup.find('form')
        if form is None :
            form = soup.find('form',method='get')
        action = form.get('action')
        method = form.get('method', 'get')
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
            temp = session.get(url,params=parameters)
            newurl = temp.url
    print('params',parameters)
    print('new :',newurl)
    return newurl
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
        postdata = session.post(url, params=parameters)
        print('POST :',postdata.url)
        urlcontain = postdata.url
    return urlcontain
def crawl_all(url,loginurl,userparam,passparam,csrfparam,username,password):
    current_ruls = crawl(url,loginurl,userparam,passparam,csrfparam,username,password)
    print("current_ruls list",current_ruls)
    all_urls = []
    for current_rul in current_ruls:
        abes = crawl(current_rul,loginurl,userparam,passparam,csrfparam,username,password)
        have_get_param = extract_form_parameters(current_rul,loginurl,userparam,passparam,csrfparam,username,password)
        if have_get_param:
            all_urls.append(have_get_param)
        for abe in abes:
            if abe not in all_urls:
                all_urls.append(abe)
    print('all', all_urls)
    return all_urls

def crawl_all_post(url,loginurl,userparam,passparam,csrfparam,username,password):
    current_ruls = crawl(url,loginurl,userparam,passparam,csrfparam,username,password)
    print("current_ruls list",current_ruls)
    all_urls = []
    for current_rul in current_ruls:
        abes = crawl(current_rul,loginurl,userparam,passparam,csrfparam,username,password)
        have_post_param = extract_post_parameters(current_rul,loginurl,userparam,passparam,csrfparam,username,password)
        if have_post_param  :
            all_urls.append(have_post_param)
    print("POST : ",all_urls)
    return all_urls
def crawl_all_get(url,loginurl,userparam,passparam,csrfparam,username,password):
    current_ruls = crawl(url,loginurl,userparam,passparam,csrfparam,username,password)
    print("current_ruls list",current_ruls)
    all_urls = []
    for current_rul in current_ruls:
        abes = crawl(current_rul,loginurl,userparam,passparam,csrfparam,username,password)
        have_get_param = extract_post_parameters(current_rul,loginurl,userparam,passparam,csrfparam,username,password)
        if have_get_param  :
            all_urls.append(have_get_param)
    return all_urls
def get_all_url_contain_param(url,loginurl,userparam,passparam,csrfparam,username,password):
    current_ruls = crawl_all(url,loginurl,userparam,passparam,csrfparam,username,password)
    print("current_ruls list",current_ruls)
    all_urls = []
    for current_rul in current_ruls:
        print("scanning url",current_rul)
        have_get_param = extract_form_parameters(current_rul,loginurl,userparam,passparam,csrfparam,username,password)
        have_post_param = extract_post_parameters(current_rul,loginurl,userparam,passparam,csrfparam,username,password)
        if have_get_param:
            all_urls.append(have_get_param)
        elif have_post_param:
            all_urls.append(have_post_param)
    return all_urls