import sqlite3
from datetime import datetime
connection = sqlite3.connect('database.db')

with open('schema.sql') as f:
    connection.executescript(f.read())

cur = connection.cursor()

cur.execute("INSERT INTO users (username,password,join_date,role,update_date,create_by) VALUES (?,?,?,?,?,?)",
            ('admin','admin','2022-04-15','Administrator',datetime.today().strftime('%Y-%m-%d'),'admin')
            )
cur.execute("INSERT INTO users (username,password,join_date,role,update_date,create_by) VALUES (?,?,?,?,?,?)",
            ('admin2','admin2',datetime.today().strftime('%Y-%m-%d'),'Administrator',datetime.today().strftime('%Y-%m-%d'),'admin')
            )
cur.execute("INSERT INTO users (username,password,join_date,role,update_date,create_by) VALUES (?,?,?,?,?,?)",
            ('trong','trong',datetime.today().strftime('%Y-%m-%d'),'Pentester',datetime.today().strftime('%Y-%m-%d'),'admin')
            )
cur.execute("INSERT INTO users (username,password,join_date,role,update_date,create_by) VALUES (?,?,?,?,?,?)",
            ('long','long',datetime.today().strftime('%Y-%m-%d'),'Project Manager',datetime.today().strftime('%Y-%m-%d'),'admin')
            )
cur.execute("INSERT INTO projects (projectname,startdate,enddate,vunls,target,create_by,securitylevel,manager,pentester,status) VALUES (?,?,?,?,?,?,?,?,?,?)",
            ('google project',datetime.today().strftime('%Y-%m-%d'),'2023-04-30',3,'https://www.google.com','1','medium','1','2','doing')
            )
cur.execute("INSERT INTO projects (projectname,startdate,enddate,vunls,target,create_by,securitylevel,manager,pentester,status) VALUES (?,?,?,?,?,?,?,?,?,?)",
            ('google project',datetime.today().strftime('%Y-%m-%d'),'2023-04-30',3,'https://public-firing-range.appspot.com','2','high','2','3','doing')
            )
connection.commit()
connection.close()