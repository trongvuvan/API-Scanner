from src.fuzzing import crawl_all,crawl_all_post,crawl_all_get,crawl,get_session,get_all_url_contain_param
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
def sqli_scan():
    return