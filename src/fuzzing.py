#!/usr/bin/python
import requests
import io
from fake_useragent import UserAgent

def directory_fuzzing(host,filepath):
    ua = UserAgent()
    user_agent = ua.random
    filepath = 'word.txt'
    directorys= []
    with open(filepath) as fp:
        line = fp.readline()
        while line:
            combined = host+line.strip()
            r = requests.get(combined, headers={'User-Agent': user_agent})
            if r.status_code == 200 or r.status_code == 302 or r.status_code == 401 or r.status_code == 500:
                print(combined.strip(),'\n',r)
                directorys.append(combined.strip())
            line = fp.readline()
    return directorys