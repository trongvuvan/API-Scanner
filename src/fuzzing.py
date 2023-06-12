import mechanicalsoup
import requests
import requests
from urllib.parse import urlparse
from urllib.parse import parse_qs
from collections import OrderedDict
from collections import Counter
headers = {"Cache-Control": "max-age=0", "sec-ch-ua": "\"Not:A-Brand\";v=\"99\", \"Chromium\";v=\"112\"", "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": "\"Windows\"", "Upgrade-Insecure-Requests": "1", "Origin": "http://127.0.0.1:3456", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.138 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Referer": "http://127.0.0.1:3456/login.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
def get_session(url,loginurl,userparam,passparam,username,password):
    s = requests.session()
    
    data = {
        userparam : username,
        passparam : password,
    }
    # 1
    browser = mechanicalsoup.StatefulBrowser()
    login_page = browser.get(loginurl)
    login_html = login_page.soup

    # 2
    form = login_html.select("form")[0]
    index = 0
    while index < len(form.select("input")):
        try: 
            data[form.select("input")[index]["name"]] = form.select("input")[index]["value"]    
        except:
            if data[form.select("input")[index]["name"]] == userparam:
                data[form.select("input")[index]["value"]] = username
            if data[form.select("input")[index]["name"]] == passparam:
                data[form.select("input")[index]["value"]] = password
        index = index + 1
    # 3 
    abe = s.post(loginurl, data=data,headers=headers)
    aba = s.get(url,headers=headers)
    return s
def crawl(url,loginurl,userparam,passparam,username,password):
    s = get_session(url,loginurl,userparam,passparam,username,password)
    url_crawled = []
    browser2 = mechanicalsoup.StatefulBrowser(session=s)
    
    r = browser2.open(url,headers=headers)
    current_page_html = browser2.get_current_page()
    links = r.soup.select("a")
    parsed_url = urlparse(url)
    for link in links:
        try:
            address = link["href"]
            newlink = parsed_url.scheme+'://'+ parsed_url.netloc + link["href"]
            url_crawled.append(newlink)
        except:
            print("yolo")
    return url_crawled

def crawl_all(url,loginurl,userparam,passparam,username,password):
    current_ruls = crawl(url,loginurl,userparam,passparam,username,password)
    print("current_ruls list",current_ruls)
    all_urls = []
    for current_rul in current_ruls:
        print("scanning url",current_rul)
        abes = crawl(current_rul,loginurl,userparam,passparam,username,password)
        for abe in abes:
            if abe not in all_urls:
                all_urls.append(abe)
    return all_urls
