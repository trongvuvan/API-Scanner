#!/usr/bin/python
import requests
import io
from fake_useragent import UserAgent

def directory_fuzzing(host):
    host = host +'/'
    ua = UserAgent()
    user_agent = ua.random
    filepath = '../wordlist.txt'
    directorys= []
    with open(filepath) as fp:
        line = fp.readline()
        while line:
            combined = host+line.strip()
            r = requests.get(combined, headers={'User-Agent': user_agent})
            if r.status_code != 404:
                print(combined.strip(),'\n',r)
                directorys.append(combined.strip())
            line = fp.readline()
    return directorys