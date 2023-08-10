from flask import Flask,Response, request, flash, url_for, redirect, render_template,session
import sqlite3
from flask_session import Session
from datetime import datetime
import flask
import time
from fpdf import FPDF
from flask_sqlalchemy_report import Reporter
import pymysql
from zapv2 import ZAPv2
import re
import os
from src.security import zapspider,zapactivescan 
from src.scan import sql_scan,path_travel_scan,rxss_scan,check_url_valid
from src.fuzzing import crawl_all,crawl_all_post,crawl_all_get,crawl,get_session,get_all_url_contain_param
import matplotlib.pyplot as plt
import sqlite3
from datetime import datetime
from src.authen import AuthenScanHeaders,au_sql_scan,au_path_travel_scan,au_rxss_scan
from src.unauthen import UnauthenScanHeaders,unau_sql_scan,unau_path_travel_scan,unau_rxss_scan
app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
apiKey = 'tp4c52en8ll0p89im4eojakbr8'

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_current_user():
    userid = session["userid"]
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE userid = ?',(userid,)).fetchone()
    conn.commit()
    conn.close()
    return user
@app.route('/reset', methods=['GET', 'POST'])
def reset():
    connection = sqlite3.connect('database.db')

    with open('schema.sql') as f:
        connection.executescript(f.read())

    cur = connection.cursor()

    cur.execute("INSERT INTO users (username,password,join_date,role,update_date,isactive,create_by) VALUES (?,?,?,?,?,?,?)",
                    ('admin','admin','2022-04-15','Administrator',datetime.today().strftime('%Y-%m-%d'),1,'admin')
                    )
    cur.execute("INSERT INTO users (username,password,join_date,role,update_date,isactive,create_by) VALUES (?,?,?,?,?,?,?)",
                    ('trong','trong',datetime.today().strftime('%Y-%m-%d'),'Pentester',datetime.today().strftime('%Y-%m-%d'),1,'admin')
                    )
    cur.execute("INSERT INTO users (username,password,join_date,role,update_date,isactive,create_by) VALUES (?,?,?,?,?,?,?)",
                    ('long','long',datetime.today().strftime('%Y-%m-%d'),'Project Manager',datetime.today().strftime('%Y-%m-%d'),1,'admin')
                    )
    cur.execute("INSERT INTO projects (projectname,startdate,enddate,vunls,target,create_by,securitylevel,manager,pentester,status,login) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    ('google project 2',datetime.today().strftime('%Y-%m-%d'),'2023-04-30',3,'http://127.0.0.1:3456','admin','medium','trong','long','doing',1)
                    )
    cur.execute("INSERT INTO projects (projectname,startdate,enddate,vunls,target,create_by,securitylevel,manager,pentester,status,login) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    ('google project',datetime.today().strftime('%Y-%m-%d'),'2023-04-30',3,'https://public-firing-range.appspot.com','admin','high','trong','long','doing',0)
                    )
    connection.commit()
    connection.close()
    return 'ok'
@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if session["userid"] is not None:
            return redirect(url_for('dashboard'))
    except:
        print('a')
    if request.method == "POST":
        details = request.form
        #retriving details from the form
        username = details['username'] 
        password = details['password']
        
        #creating a DB connection
        cur = get_db_connection()
        isactive = cur.execute('SELECT * FROM users WHERE username = ? AND isactive = ?',(username,0,)).fetchone()
        if isactive is not None:
            msg = 'Account is inactive'
            return render_template('login.html',msg=msg)
        account = cur.execute('SELECT * FROM users WHERE username = ? AND password = ?',(username,password,)).fetchone()
        cur.commit()
        cur.close()
        if account is not None:
            session["userid"] = account["userid"]
            return redirect(url_for('dashboard'))
        else:
            msg = 'Username or password is incorrect'
            return render_template('login.html',msg=msg)
    return render_template('login.html')
@app.route("/myprofile")
def profile():
    msg =''
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    cur = get_db_connection()
    userid = session["userid"]
    user = cur.execute('SELECT * FROM users WHERE userid = ?',(userid,)).fetchall()
    projects = cur.execute('SELECT * FROM users,projects WHERE (username = manager OR username = pentester) AND userid = ?',(userid,)).fetchall()
    cur.commit()
    cur.close()
    if user is not None:
        return render_template('profile.html',currentuser=currentuser,projects=projects,user=user,msg=msg)
    else:
        return 'user not exist'
@app.route('/add-user', methods=('GET', 'POST'))
def add_user():
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    if currentuser["role"] != 'Administrator':
        return render_template('403.html',)
    conn = get_db_connection()
    msg = ''
    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        password = request.form['password']
        confirmpassword = request.form['confirmpassword']
        currentuser= get_current_user()
        create_by = currentuser["username"]
        isactive = 1
        exist = conn.execute('SELECT * FROM users WHERE username = ?',(username,)).fetchone()
        msg = ''
        if not username or not role or not password or not confirmpassword:
            msg = 'Something is missing!'
        else:
            if exist is not None:
                msg = 'Username existed'
            else:
                if confirmpassword != password:
                    msg = 'Password not match!'
                else:
                    msg = 'Add user successfully'
                    conn = get_db_connection()
                    conn.execute('INSERT INTO users (username,password,join_date,role,update_date,isactive,create_by) VALUES (?,?,?,?,?,?,?)',
                            (username,password,datetime.today().strftime('%Y-%m-%d'),role,datetime.today().strftime('%Y-%m-%d'),isactive,create_by))
                    conn.commit()
                    conn.close()
                    return redirect(url_for('showuser'))
    return render_template('add_user.html',msg=msg,currentuser=currentuser)
@app.route("/search_user", methods=['GET', 'POST'])
def search_user():
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    if currentuser["role"] != 'Administrator':
        return render_template('403.html',)
    msg = ''
    if request.method == 'GET':
        username = request.args.get('username')
        conn = get_db_connection()
        users = conn.execute("SELECT * FROM users WHERE username LIKE ?", ('%' + username + '%',)).fetchall()
        conn.commit()
        conn.close()
        if users is not None:
            return render_template('show_user.html',currentuser=currentuser, users = users ,msg = msg)
        else: 
            msg = 'User not found'
            return render_template('show_user.html',currentuser=currentuser, users = users ,msg = msg)
        
@app.route("/change-pass", methods=['GET', 'POST'])
def changepwd():
    msg = ''
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    if request.method == 'POST':
        currentpasswd = currentuser["password"]
        oldpassword = request.form['oldpassword']
        newpassword = request.form['newpassword']
        repassword = request.form['repassword']
        if newpassword != repassword:
            msg='Passwords do not match'
            return render_template('changes_pass.html', msg = msg)
        if oldpassword != currentpasswd:
            msg='Passwords wrong'
            return render_template('changes_pass.html', msg = msg)
        msg = 'update password successfully'
        conn = get_db_connection()
        exist = conn.execute('UPDATE users SET password=? WHERE userid = ?',(newpassword,currentuser["userid"])).fetchone()
        user = conn.execute('SELECT * FROM users WHERE userid = ?',(currentuser["userid"],)).fetchall()
        conn.commit()
        conn.close()
        projects = cur.execute('SELECT * FROM users,projects WHERE (username = manager OR username = pentester) AND userid = ?',(userid,)).fetchall()
        return render_template('profile.html',projects=projects,currentuser=currentuser,user=user,msg = msg)
    return render_template('changes_pass.html',currentuser=currentuser, msg = msg)
@app.route("/about-us")
def about_us():
    return render_template('about_us.html')
@app.route("/logout")
def logout():
    session["userid"] = None
    return redirect(url_for('login'))
@app.route("/",methods=('GET', 'POST'))
def index():
    try :
        if session["userid"] is not None:
            return redirect(url_for('dashboard'))
    except:
        print('a')
    if request.method == "POST":
        details = request.form
        #retriving details from the form
        username = details['username'] 
        password = details['password']
        
        #creating a DB connection
        cur = get_db_connection()
        isactive = cur.execute('SELECT * FROM users WHERE username = ? AND isactive = ?',(username,0,)).fetchone()
        if isactive is not None:
            msg = 'Account is inactive'
            return render_template('login.html',msg=msg)
        account = cur.execute('SELECT * FROM users WHERE username = ? AND password = ?',(username,password,)).fetchone()
        cur.commit()
        cur.close()
        if account is not None:
            session["userid"] = account["userid"]
            return redirect(url_for('dashboard'))
        else:
            msg = 'Username or password is incorrect'
            return render_template('login.html',msg=msg)
    return render_template('login.html')
@app.route("/dashboard")
def dashboard():
    try: 
        if session["userid"] == None:
            return redirect(url_for('login'))
    except:
        print('a')
    if session["userid"] is not None:
        currentuser = get_current_user()
        conn = get_db_connection()
        critical = conn.execute('SELECT count(bugid) FROM bugs WHERE risk = ? AND pentester = ?',('Critial',currentuser["username"],)).fetchone()
        total_critical = critical['count(bugid)']
        conn.commit()
        
        high = conn.execute('SELECT count(bugid) FROM bugs WHERE risk = ? AND pentester = ?',('High',currentuser["username"],)).fetchone()
        total_high = high['count(bugid)']
        conn.commit()
        
        medium = conn.execute('SELECT count(bugid) FROM bugs WHERE risk = ? AND pentester = ?',('Medium',currentuser["username"],)).fetchone()
        total_medium = medium['count(bugid)']
        conn.commit()
        
        low = conn.execute('SELECT count(bugid) FROM bugs WHERE risk = ? AND pentester = ?',('Low',currentuser["username"],)).fetchone()
        total_low = low['count(bugid)']
        conn.commit()
        
        info = conn.execute('SELECT count(bugid) FROM bugs WHERE risk = ? AND pentester = ?',('Informational',currentuser["username"],)).fetchone()
        total_info = info['count(bugid)']
        conn.commit()
        
        bugs = conn.execute('SELECT name,count(bugid) FROM bugs WHERE pentester = ? group by name',(currentuser["username"],)).fetchall()
        conn.commit()
    else:
        render_template('base.html')
    return render_template('dashboard.html',total_critical=total_critical,total_high=total_high,total_medium=total_medium,total_low=total_low,total_info=total_info,bugs=bugs)
@app.route("/enableaccount", methods=('GET', 'POST'))
def enableaccount():
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    if currentuser["role"] != 'Administrator':
        return render_template('403.html',)
    msg = ''
    if request.method == 'POST':
        conn = get_db_connection()
        userid = request.form['userid']
        exist = conn.execute('UPDATE users set update_by = ?,isactive = ? WHERE userid = ?',(currentuser["username"],1,userid,)).fetchone()
        conn.commit()
        conn.close()
        msg = ''
        if exist is None:
            msg ='Update sucessfully'
        else:
            msg = 'An error occurred while updateing'
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.commit()
    conn.close()
    return render_template('show_user.html', currentuser=currentuser,users=users,msg=msg)
@app.route('/usermanager', methods=('GET', 'POST'))
def showuser():
    msg = ''
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    if currentuser["role"] != 'Administrator':
        return render_template('403.html',)
    ### DEACTIVE USER
    if request.method == 'POST':
        conn = get_db_connection()
        userid = request.form['userid']
        exist = conn.execute('UPDATE users set update_by = ?,isactive = ? WHERE userid = ?',(currentuser["username"],0,userid,)).fetchone()
        conn.commit()
        conn.close()
        msg = ''
        if exist is None:
            msg ='Update sucessfully'
        else:
            msg = 'An error occurred while Updateing'
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.commit()
    conn.close()
    return render_template('show_user.html',currentuser=currentuser, users=users,msg=msg)
@app.route('/leaderboard', methods=('GET', 'POST'))
def leaderboard():
    if session["userid"] == None:
        return redirect(url_for('login'))
    conn = get_db_connection()
    data = {}
    users = conn.execute('SELECT username FROM users').fetchall()
    totals = conn.execute("SELECT bugs.pentester,count(bugid),testdate FROM bugs,requests WHERE requests.requestid = bugs.requestid AND strftime('%Y-%m', testdate)  = ? group by bugs.pentester ", (datetime.today().strftime('%Y-%m'),)).fetchall()
    #datas = sorted(totals, key=lambda x: x['cound(bugid)'], reverse=True)
    current_month = datetime.now().month
    current_year = datetime.now().year
    datas = sorted(totals, key=lambda x: x[1], reverse=True)
    return render_template('leaderboard.html',users=users,datas=datas,current_month=current_month,current_year=current_year)
@app.route('/edituser/<int:id>', methods=('GET', 'POST'))
def edituser(id):
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    if currentuser["role"] != 'Administrator':
        return render_template('403.html',)
    msg=''
    if session["userid"] == None:
        return redirect(url_for('login'))
    conn = get_db_connection()
    update = conn.execute('SELECT * FROM users WHERE userid = ?',(id,)).fetchall()
    conn.commit()
    conn.close()
    if update is not None:
        if request.method == 'POST':
            role = request.form['role']
            update_date = datetime.today().strftime('%Y-%m-%d')
            update_by = currentuser["username"]
            if not role:
                role = currentuser['role']
            else:
                conn = get_db_connection()
                exist = conn.execute('UPDATE users SET role=?,update_date=?,update_by=?WHERE userid = ?',(role,update_date,update_by,id,)).fetchone()
                conn.commit()
                conn.close()
                if exist is not None:
                    msg='Cannot edit user'
                else:
                    msg='Edit successfully'
                    conn = get_db_connection()
                    users = conn.execute('SELECT * FROM users').fetchall()
                    update = conn.execute('SELECT * FROM users WHERE userid = ?',(id,)).fetchall()
                    conn.commit()
                    conn.close()
                    return render_template('show_user.html', currentuser=currentuser,users=users,msg=msg)
        return render_template('edit_user.html',currentuser=currentuser, update=update,msg=msg)
        
        
## PROJECT ##
        
        
@app.route('/projectmanager', methods=('GET', 'POST'))
def showproject():
    msg = ''
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    conn = get_db_connection()
    projects = conn.execute('SELECT * FROM projects where pentester = ? OR manager = ?',(currentuser["username"],currentuser["username"],)).fetchall()
    allprojects = conn.execute('SELECT * FROM projects').fetchall()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.commit()
    conn.close()
    return render_template('show_project.html', allprojects=allprojects,currentuser=currentuser,projects=projects,users=users,msg=msg)
@app.route('/cookies-config/<int:id>', methods=('GET', 'POST'))
def cookies_config(id):
    conn = get_db_connection()
    msg = ''
    if session["userid"] == None:
        return redirect(url_for('login'))
    role = conn.execute('SELECT * FROM projects WHERE projectid = ?',(id,)).fetchone()
    currentuser = get_current_user()
    if currentuser["username"] != role["pentester"]:
        if currentuser["username"] == role["manager"]:
            print("")
        elif currentuser["role"] == 'Administrator':
            print("")
        else:
            return render_template('403.html',)
    if request.method == 'POST':
        loginurl = request.form["loginurl"]
        userparam = request.form['usernameparameter']
        passparam = request.form['passwordparameter']
        csrfparam = request.form['csrfparam']
        username = request.form['username']
        password = request.form['password']
        isconfig = 1
        conn.execute('INSERT INTO sessions (projectid,loginurl,userparam,passparam,csrfparam,username,password) VALUES (?,?,?,?,?,?,?)',
                    (id,loginurl,userparam,passparam,csrfparam,username,password))
        conn.commit()
        conn.execute('UPDATE projects SET isconfig=? WHERE projectid=?',
                        (isconfig,id,)).fetchone()
        conn.commit()
        conn = get_db_connection()
        projects = conn.execute('SELECT * FROM projects where pentester = ? OR manager = ?',(currentuser["username"],currentuser["username"],)).fetchall()
        allprojects = conn.execute('SELECT * FROM projects').fetchall()
        users = conn.execute('SELECT * FROM users').fetchall()
        conn.commit()
        conn.close()
        return render_template('show_project.html',allprojects=allprojects, currentuser=currentuser,projects=projects,users=users,msg=msg)
    conn.close()
    return render_template('config.html')
@app.route('/cookies-update/<int:id>', methods=('GET', 'POST'))
def cookies_update(id):
    msg = ''
    conn = get_db_connection()
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    role = conn.execute('SELECT * FROM projects WHERE projectid = ?',(id,)).fetchone()
    if currentuser["username"] != role["pentester"]:
        if currentuser["username"] == role["manager"]:
            print("")
        elif currentuser["role"] == 'Administrator':
            print("")
        else:
            return render_template('403.html',)
    
    if request.method == 'POST':
        loginurl = request.form["loginurl"]
        userparam = request.form['usernameparameter']
        passparam = request.form['passwordparameter']
        csrfparam = request.form['csrfparam']
        username = request.form['username']
        password = request.form['password']
        isconfig = 1
        conn.execute('UPDATE sessions SET loginurl = ? ,userparam = ?,passparam = ?,csrfparam =?, username = ?,password = ? WHERE projectid = ?',
                    (loginurl,userparam,passparam,csrfparam,username,password,id,))
        conn.commit()
        conn.execute('UPDATE projects SET isconfig=? WHERE projectid=?',
                        (isconfig,id,)).fetchone()
        conn.commit()
        conn = get_db_connection()
        projects = conn.execute('SELECT * FROM projects where pentester = ? OR manager = ?',(currentuser["username"],currentuser["username"],)).fetchall()
        allprojects = conn.execute('SELECT * FROM projects').fetchall()
        users = conn.execute('SELECT * FROM users').fetchall()
        conn.commit()
        conn.close()
        return render_template('show_project.html',allprojects=allprojects, currentuser=currentuser,projects=projects,users=users,msg=msg)
    projectdata = conn.execute('SELECT * FROM sessions WHERE projectid = ?',(id,)).fetchone()
    conn.commit()
    conn.close()
    return render_template('session_update.html',projectdata=projectdata)
@app.route('/editproject/<int:id>', methods=('GET', 'POST'))
def editproject(id):
    msg = ''
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    conn = get_db_connection()
    if currentuser["role"] == 'Pentester':
        return render_template('403.html',)
    role = conn.execute('SELECT * FROM projects WHERE projectid = ?',(id,)).fetchone()
    if currentuser["role"] != 'Administrator':
        if currentuser["username"] != role["manager"]:
            return render_template('403.html',)
    projects = conn.execute('SELECT * FROM projects WHERE projectid = ?',(id,)).fetchall()
    project = conn.execute('SELECT * FROM projects WHERE projectid = ?',(id,)).fetchone()
    users = conn.execute('SELECT * FROM users').fetchall()
    if request.method == 'POST':
        projectname = request.form['projectname']
        target = request.form['target']
        manager = request.form['manager']
        pentester = request.form['pentester']
        status = request.form['status']
        exist = conn.execute('SELECT * FROM projects WHERE projectname = ?',(projectname,)).fetchone()
        if exist is not None:
            msg = 'Project Name already existed'
            return render_template('edit_project.html', projects=projects,users=users,msg=msg)
        if not projectname:
            projectname = project["projectname"]
        if not target:
            target = project["target"]
        if not manager:
            manager = project["manager"]
        if not pentester:
            pentester = project["pentester"]
        if not status:
            status = project["status"]
        msg = 'UPDATE Project successfully'
        conn = get_db_connection()
        conn.execute('UPDATE projects SET projectname=?,target=?,manager=?,pentester=?,status=? WHERE projectid=?',
                        (projectname,target,manager,pentester,status,id,)).fetchone()
        conn.commit()
        conn.close()
        return redirect(url_for('showproject'))
    
    return render_template('edit_project.html',currentuser=currentuser, projects=projects,users=users,msg=msg)
@app.route('/deleteproject/<int:id>', methods=('GET', 'POST'))
def deleteproject(id):
    msg = ''
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    if currentuser["role"] == 'Pentester':
        return render_template('403.html',)
    conn = get_db_connection()
    update = conn.execute('DELETE FROM projects WHERE projectid = ?',(id,)).fetchall()
    projects = conn.execute('SELECT * FROM projects where pentester = ? OR manager = ?',(currentuser["username"],currentuser["username"],)).fetchall()
    allprojects = conn.execute('SELECT * FROM projects').fetchall()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.commit()
    conn.close()
    return render_template('show_project.html',allprojects=allprojects,currentuser=currentuser, projects=projects,users=users,msg=msg)
@app.route('/create-project', methods=('GET', 'POST'))
def add_project():
    msg = ''
    conn = get_db_connection()
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    if currentuser["role"] == 'Pentester':
        return render_template('403.html',)
    users = conn.execute('SELECT * FROM users').fetchall()
    if request.method == 'POST':
        projectname = request.form['projectname']
        startdate = request.form['startdate']
        target = request.form['target']
        manager = request.form['manager']   
        pentester = request.form['pentester']
        loginrequired = 0
        try :
            loginrequired = request.form['loginrequired']
        except:
            print('no')
        status = 'Pending'
        exist = conn.execute('SELECT * FROM projects WHERE projectname = ?',(projectname,)).fetchone()
        if exist is not None:
            msg = 'Project Name already existed'
            return render_template('add_project.html',users=users,msg=msg)
        else:
            msg = 'Create Project successfully'
            conn = get_db_connection()
            conn.execute("INSERT INTO projects (projectname,startdate,target,create_by,manager,pentester,status,login) VALUES (?,?,?,?,?,?,?,?)",
                        (projectname,startdate,target,currentuser["username"],manager,pentester,status,loginrequired))
            conn.commit()
            projects = conn.execute('SELECT * FROM projects where pentester = ? OR manager = ?',(currentuser["username"],currentuser["username"],)).fetchall()
            allprojects = conn.execute('SELECT * FROM projects').fetchall()
            conn.commit()
            conn.close()
            return render_template('show_project.html',allprojects=allprojects,currentuser=currentuser, projects = projects,users=users,msg = msg)
    return render_template('add_project.html',currentuser=currentuser,users=users,msg=msg)
@app.route("/search_project", methods=['GET', 'POST'])
def search_project():
    
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    msg = ''
    if request.method == 'GET':
        projectname = request.args.get('projectname')
        conn = get_db_connection()
        projects = conn.execute('SELECT * FROM projects WHERE projectname like ?',('%'+projectname+'%',)).fetchall()
        users = conn.execute('SELECT * FROM users').fetchall()
        conn.commit()
        conn.close()
        if projects is not None:
            return render_template('show_project.html', currentuser=currentuser,projects = projects,users=users ,msg = msg)
        else: 
            msg = 'Project not found'
            return render_template('show_project.html',currentuser=currentuser, projects = projects,users=users,msg = msg)
@app.route('/project-detail/<int:id>', methods=('GET', 'POST'))
def project_detail(id):
    msg = ''
    conn = get_db_connection()
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    project = conn.execute('SELECT * FROM projects WHERE projectid = ?',(id,)).fetchone()
    if currentuser["username"] != project["pentester"]:
        if currentuser["username"] == project["manager"]:
            print("")
        elif currentuser["role"] == 'Administrator':
            print("")
        else:
            return render_template('403.html',)
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users',).fetchall()
    havebugs = conn.execute('SELECT * FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ? AND bugs.requestid in (SELECT requestid FROM bugs) GROUP BY bugs.requestid',(id,)).fetchall()
    requests = conn.execute('SELECT * FROM requests WHERE projectid = ?',(id,)).fetchall()
    total = conn.execute('SELECT count(requestid) FROM requests WHERE projectid = ?',(id,)).fetchone()
    totalrequest = total["count(requestid)"]
    done = conn.execute('SELECT count(requestid) FROM requests WHERE status = ? AND projectid = ?',("Done",id,)).fetchone()
    donerequest = done["count(requestid)"]
    remain = total["count(requestid)"] - done["count(requestid)"]
    if remain == 0 and totalrequest != 0:
        updateprj = conn.execute('UPDATE projects SET status = ?,enddate= ? WHERE projectid = ?',("Done",datetime.today().strftime('%Y-%m-%d'),id,))
    conn.commit()
    
    bugs = conn.execute('SELECT bugs.name,count(bugid),risk FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ? GROUP BY bugs.name',(id,)).fetchall()
    conn.commit()
    conn.close()
    return render_template('project_detail.html',bugs=bugs,currentuser=currentuser,havebugs=havebugs,users=users,project=project,totalrequest=totalrequest,donerequest=donerequest,remain=remain,requests=requests,msg=msg)
@app.route('/bug-detail/<int:id>', methods=('GET', 'POST'))
def bug_detail(id):
    # id = requestid
    msg = ''
    conn = get_db_connection()
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    conn = get_db_connection()
    requesturl = conn.execute('SELECT requesturl FROM requests WHERE requestid = ?',(id,)).fetchone()
    bugs = conn.execute('SELECT * FROM bugs WHERE bugurl LIKE ?',(requesturl["requesturl"],)).fetchall()
    return render_template('bug_detail.html',request=request,currentuser=currentuser,bugs=bugs,msg=msg)
##########################################################################
########################## SECURITY ########################################
##########################################################################
@app.route('/spider-scan/<int:id>', methods=('GET', 'POST'))
def spiderscan(id):
    msg = ''
    conn = get_db_connection()
    currentuser = get_current_user()
    target = conn.execute('SELECT * FROM projects WHERE projectid = ?',(id,)).fetchone()
    if currentuser["username"] != target["pentester"]:
        if currentuser["username"] == target["manager"]:
            print("")
        elif currentuser["role"] == 'Administrator':
            print("")
        else:
            return render_template('403.html',)
    conn.commit()
    if target['isspider'] == 1:
        msg = ' Have been spidered'
        allprojects = conn.execute('SELECT * FROM projects').fetchall()
        projects = conn.execute('SELECT * FROM projects where pentester = ? OR manager = ?',(currentuser["username"],currentuser["username"],)).fetchall()
        users = conn.execute('SELECT * FROM users').fetchall()
        conn.commit()
        conn.close()
        return render_template('show_project.html',allprojects=allprojects, currentuser=currentuser,projects=projects,users=users,msg=msg)
    if target['login'] == 0:
        spiderresults = zapspider(target["target"])
        isspider = 1
        conn = get_db_connection()
        conn.execute('UPDATE projects SET isspider = ?,status = ? WHERE projectid = ?',
                            (isspider,"Doing",id,)).fetchone()
        conn.commit()
        print(spiderresults)
        allfounds = spiderresults
        print('all',allfounds)
        for result in allfounds:
            print('for loop',result)
            if result is not None:
                duplicate = conn.execute('SELECT * FROM requests WHERE requesturl = ? AND projectid = ?',(result,id,)).fetchone()
                if duplicate is None:
                    status = 'Pending'
                    isscan = 0
                    conn2 = get_db_connection()
                    conn2.execute('INSERT INTO requests (projectid,requesturl,haveparam,status,isscan) VALUES (?,?,?,?,?)',
                                        (id,result,'GET',status,isscan,))
                    conn2.commit()
                    conn2.close()
    if target['Login'] == 1:
        checklogin = conn.execute('SELECT * FROM projects WHERE login = 1 AND projectid in( select projectid from sessions where projectid = ?)',(id,)).fetchone()
        if checklogin is None:
            msg = 'Please config session'
            projects = conn.execute('SELECT * FROM projects where pentester = ? OR manager = ?',(currentuser["username"],currentuser["username"],)).fetchall()
            users = conn.execute('SELECT * FROM users').fetchall()
            allprojects = conn.execute('SELECT * FROM projects').fetchall()
            conn.commit()
            conn.close()
            return render_template('show_project.html',allprojects=allprojects, currentuser=currentuser,projects=projects,users=users,msg=msg)
        isspider = 1
        conn = get_db_connection()
        conn.execute('UPDATE projects SET isspider=?,status=? WHERE projectid=?',
                            (isspider,"Doing",id,)).fetchone()
        data = conn.execute('SELECT * FROM sessions WHERE projectid = ?',(id,)).fetchone()
        conn.commit()
        fuzzresults = crawl_all(target["target"],data["loginurl"],data["userparam"],data["passparam"],data["csrfparam"],data["username"],data["password"])
        post_urls = crawl_all_post(target["target"],data["loginurl"],data["userparam"],data["passparam"],data["csrfparam"],data["username"],data["password"])
        isfuzzing = 1
        conn.execute('UPDATE projects SET status=? WHERE projectid=?',
                            ("Doing",id,)).fetchone()
        conn.commit()
        for post_url in post_urls:    
            if post_url is not None:
                duplicate = conn.execute('SELECT * FROM requests WHERE requesturl = ? AND projectid = ?',(post_url,id,)).fetchone()
                if duplicate is None:    
                    status = 'Pending'
                    isscan = 0
                    parampost = 'POST'
                    conn.execute('INSERT INTO requests (projectid,requesturl,status,isscan,haveparam) VALUES (?,?,?,?,?)',
                                        (id,post_url,status,isscan,parampost))
                    conn.commit()
        for fuzzresult in fuzzresults:    
            if fuzzresult is not None:
                duplicate = conn.execute('SELECT * FROM requests WHERE requesturl = ? AND projectid = ?',(fuzzresult,id,)).fetchone()
                if duplicate is None:    
                    status = 'Pending'
                    isscan = 0
                    paramsget = 'GET'
                    conn.execute('INSERT INTO requests (projectid,requesturl,status,isscan,haveparam) VALUES (?,?,?,?,?)',
                                        (id,fuzzresult,status,isscan,paramsget))
                    conn.commit()
    projects = conn.execute('SELECT * FROM projects where pentester = ? OR manager = ?',(currentuser["username"],currentuser["username"],)).fetchall()
    allprojects = conn.execute('SELECT * FROM projects').fetchall()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.commit()
    conn.close()
    return render_template('show_project.html',allprojects=allprojects, currentuser=currentuser,projects=projects,users=users,msg=msg)
@app.route('/activescan/<int:id>', methods=('GET', 'POST'))
def activescan(id):
    msg = ''
    currentuser = get_current_user()
    conn = get_db_connection()
    target = conn.execute('SELECT * FROM requests WHERE requestid = ?',(id,)).fetchone()
    conn.commit()
    projectid = target["projectid"]
    check = conn.execute('SELECT * FROM projects WHERE projectid = ?',(projectid,)).fetchone()
    if currentuser["username"] != check["pentester"]:
        if currentuser["username"] == check["manager"]:
            print("")
        elif currentuser["role"] == 'Administrator':
            print("")
        else:
            return render_template('403.html',)
    requesturl = target["requesturl"]
    conn = get_db_connection()
    isscan = 1
    conn.execute('UPDATE requests SET isscan= ?,status = ?,pentester=?,testdate = ? WHERE requestid=?',
                        (isscan,"Done",currentuser["username"],datetime.today().strftime('%Y-%m-%d'),id,)).fetchone()
    conn.commit()

    if check["login"] == 0:
        request_have_bug = 0
        scan = UnauthenScanHeaders(target["requesturl"])
        x_xss = scan.scan_xxss()
        if x_xss == True:
            request_have_bug = 1
            conn = get_db_connection()
            name = 'X-XSS-Protection Header is missing'
            bugurl = target["requesturl"]
            method = 'GET'
            cweid = 'CWE-693'
            confidence = 'Informational'
            risk = 'Informational'
            description = '''
Invicti detected a missing X-XSS-Protection header which means that this website could be at risk of a Cross-site Scripting (XSS) attacks.
            '''
            solution = '''
Add the X-XSS-Protection header with a value of "1; mode= block".
    X-XSS-Protection: 1; mode=block
Please also be advised that in some specific cases enabling XSS filter can be abused by attackers. However, in most cases, it provides basic protection for users against XSS attacks.
            '''
            pentester = currentuser['username']
            reference = '''
https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/missing-x-xss-protection-header/
            '''
            duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
            if duplicate is None:
                conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            method.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            confidence.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1')))
                conn.commit()  
        nosniff = scan.scan_nosniff()
        if nosniff == True:
            request_have_bug = 1
            conn = get_db_connection()
            name = 'X-Content-Type-Options Header is Missing'
            bugurl = target["requesturl"]
            method = 'GET'
            cweid = 'CWE-643'
            confidence = 'Low'
            risk = 'Low'
            description = '''
The Anti-MIME-Sniffing header X-Content-Type-Options was not set to ’nosniff’. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.
            '''
            solution = '''
Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages. If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.
            '''
            pentester = currentuser['username']
            reference = '''
https://www.iothreat.com/blog/x-content-type-options-header-missing#:~:text=The%20'X%2DContent%2DType,perform%20content%2Dtype%20sniffing%20attacks.
https://www.zaproxy.org/docs/alerts/10021/
http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx
            '''
            duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
            if duplicate is None:
                conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            method.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            confidence.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1')))
                conn.commit() 

        xframe = scan.scan_xframe()
        if xframe == True:
            request_have_bug = 1
            conn = get_db_connection()
            name = 'X-Frame-Options Header is Missing'
            bugurl = target["requesturl"]
            method = 'GET'
            cweid = 'CWE-613'
            confidence = 'Low'
            risk = 'Low'
            description = '''
The X-Frame-Options HTTP header field indicates a policy that specifies whether the browser should render the transmitted resource within a frame or an iframe. Servers can declare this policy in the header of their HTTP responses to prevent clickjacking attacks, which ensures that their content is not embedded into other pages or frames.
            '''
            solution = '''
Sending the proper X-Frame-Options in HTTP response headers that instruct the browser to not allow framing from other domains.
    X-Frame-Options: DENY  It completely denies to be loaded in frame/iframe.
    X-Frame-Options: SAMEORIGIN It allows only if the site which wants to load has a same origin.
    X-Frame-Options: ALLOW-FROM URL It grants a specific URL to load itself in a iframe. However please pay attention to that, not all browsers support this.
Employing defensive code in the UI to ensure that the current frame is the most top level window.
            '''
            pentester = currentuser['username']
            reference = '''
            https://www.iothreat.com/blog/x-content-type-options-header-missing#:~:text=The%20'X%2DContent%2DType,perform%20content%2Dtype%20sniffing%20attacks.
            '''
            duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
            if duplicate is None:
                conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            method.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            confidence.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1')))
                conn.commit()  

        hsts = scan.scan_hsts()
        if hsts == True:
            request_have_bug = 1
            conn = get_db_connection()
            name = 'Strict-Transport-Security Header is Missing'
            bugurl = target["requesturl"]
            method = 'GET'
            cweid = 'CWE-523'
            confidence = 'Medium'
            risk = 'Medium'
            description = '''
            The HTTP protocol by itself is clear text, meaning that any data that is transmitted via HTTP can be captured and the contents viewed. To keep data private and prevent it from being intercepted, HTTP is often tunnelled through either Secure Sockets Layer (SSL) or Transport Layer Security (TLS). When either of these encryption standards are used, it is referred to as HTTPS.

HTTP Strict Transport Security (HSTS) is an optional response header that can be configured on the server to instruct the browser to only communicate via HTTPS. This will be enforced by the browser even if the user requests a HTTP resource on the same server.

Cyber-criminals will often attempt to compromise sensitive information passed from the client to the server using HTTP. This can be conducted via various Man-in-The-Middle (MiTM) attacks or through network packet captures.

Scanner discovered that the affected application is using HTTPS however does not use the HSTS header.
            
            '''
            solution = '''
            Depending on the framework being used the implementation methods will vary, however it is advised that the `Strict-Transport-Security` header be configured on the server.
One of the options for this header is `max-age`, which is a representation (in milliseconds) determining the time in which the client's browser will adhere to the header policy.
Depending on the environment and the application this time period could be from as low as minutes to as long as days.
            
            '''
            pentester = currentuser['username']
            reference = '''
https://kinsta.com/knowledgebase/hsts-missing-from-https-server/#:~:text=Sometimes%2C%20an%20IT%20security%20scan,as%20a%20medium%2Drisk%20vulnerability.
https://www.ibm.com/support/pages/resolving-missing-hsts-or-missing-http-strict-transport-security-websphere
            '''
            duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
            if duplicate is None:
                conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            method.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            confidence.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1')))
                conn.commit()  

        policy = scan.scan_policy()
        if policy == True:
            request_have_bug = 1
            conn = get_db_connection()
            name = 'Content Security Policy (CSP) not implemented'
            bugurl = target["requesturl"]
            method = 'GET'
            cweid = 'CWE-523'
            confidence = 'Medium'
            risk = 'Medium'
            description = '''
Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks.

Content Security Policy (CSP) can be implemented by adding a Content-Security-Policy header. The value of this header is a string containing the policy directives describing your Content Security Policy. To implement CSP, you should define lists of allowed origins for the all of the types of resources that your site utilizes
            
            '''
            solution = '''
It's recommended to implement Content Security Policy (CSP) into your web application. Configuring Content Security Policy involves adding the Content-Security-Policy HTTP header to a web page and giving it values to control resources the user agent is allowed to load for that page.
            '''
            pentester = currentuser['username']
            reference = '''
https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
https://hacks.mozilla.org/2016/02/implementing-content-security-policy/
            '''
            duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
            if duplicate is None:
                conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            method.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            confidence.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1')))
                conn.commit()  

        cors = scan.scan_cors()
        if cors == True:
            request_have_bug = 1
            conn = get_db_connection()
            name = 'Content Security Policy (CSP) not implemented'
            bugurl = target["requesturl"]
            method = 'GET'
            cweid = 'CWE-523'
            confidence = 'Medium'
            risk = 'Medium'
            description = '''
CORS is a security feature created to selectively relax the SOP restrictions and enable controlled access to resources from different domains. CORS rules allow domains to specify which domains can request information from them by adding specific HTTP headers in the response. There are several HTTP headers related to CORS, but we are interested in the two related to the commonly seen vulnerabilities — Access-Control-Allow-Origin and Access-Control-Allow-Credentials. Access-Control-Allow-Origin: This header specifies the allowed domains to read the response contents. The value can be either a wildcard character (*), which indicates all domains are allowed, or a comma-separated list of domains.
            '''
            solution = '''
It’s primarily web server misconfigurations that enable CORS vulnerabilities. The solution is to prevent the vulnerabilities from arising in the first place by properly configuring your web server’s CORS policies
    1. Specify the allowed origins
    2. Only allow trusted sites
    3. Don’t whitelist “null”
    4. Implement proper server-side security policies
            '''
            pentester = currentuser['username']
            reference = '''
https://www.freecodecamp.org/news/exploiting-cors-guide-to-pentesting/
https://ranakhalil.teachable.com/p/web-security-academy-video-series
            '''
            duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
            if duplicate is None:
                conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            method.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            confidence.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1')))
                conn.commit() 

        server = scan.scan_server()
        if server == True:
            request_have_bug = 1
            conn = get_db_connection()
            name = "Server Leaks Information via 'X-Powered-By' HTTP Response Header Field(s)"
            bugurl = target["requesturl"]
            method = 'GET'
            cweid = 'CWE-200'
            confidence = 'Medium'
            risk = 'Medium'
            description = '''
The web/application server is leaking information via one or more “X-Powered-By” HTTP response headers. Access to such information may facilitate attackers identifying other frameworks/components your web application is reliant upon and the vulnerabilities such components may be subject to.
            '''
            solution = '''
Ensure that your web server, application server, load balancer, etc. is configured to suppress 'X-Powered-By' headers.
            '''
            pentester = currentuser['username']
            reference = '''
http://blogs.msdn.com/b/varunm/archive/2013/04/23/remove-unwanted-http-response-headers.aspx
http://www.troyhunt.com/2012/02/shhh-dont-let-your-response-headers.html
            '''
            duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
            if duplicate is None:
                conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            method.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            confidence.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1')))
                conn.commit() 

        for cookie in scan.cookies:
            cookiecure =scan.scan_secure(cookie)
            if cookiecure == True:
                request_have_bug = 1
                conn = get_db_connection()
                name = 'TLS cookie without secure flag set'
                bugurl = target["requesturl"]
                method = 'GET'
                cweid = 'CWE-614'
                confidence = 'Medium'
                risk = 'Medium'
                description = '''
If the secure flag is set on a cookie, then browsers will not submit the cookie in any requests that use an unencrypted HTTP connection, thereby preventing the cookie from being trivially intercepted by an attacker monitoring network traffic. If the secure flag is not set, then the cookie will be transmitted in clear-text if the user visits any HTTP URLs within the cookie's scope. An attacker may be able to induce this event by feeding a user suitable links, either directly or via another web site. Even if the domain that issued the cookie does not host any content that is accessed over HTTP, an attacker may be able to use links of the form http://example.com:443/ to perform the same attack.
                '''
                solution = '''
The secure flag should be set on all cookies that are used for transmitting sensitive data when accessing content over HTTPS. If cookies are used to transmit session tokens, then areas of the application that are accessed over HTTPS should employ their own session handling mechanism, and the session tokens used should never be transmitted over unencrypted communications.
                '''
                pentester = currentuser['username']
                reference = '''
https://owasp.org/www-community/controls/SecureCookieAttribute
                '''
                duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
                if duplicate is None:
                    conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                                (id,
                                                name.encode('latin-1', 'replace').decode('latin-1'),
                                                bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                                method.encode('latin-1', 'replace').decode('latin-1'),
                                                cweid.encode('latin-1', 'replace').decode('latin-1'),
                                                confidence.encode('latin-1', 'replace').decode('latin-1'),
                                                description.encode('latin-1', 'replace').decode('latin-1'),
                                                solution.encode('latin-1', 'replace').decode('latin-1'),
                                                risk.encode('latin-1', 'replace').decode('latin-1'),
                                                reference.encode('latin-1', 'replace').decode('latin-1'),
                                                pentester.encode('latin-1', 'replace').decode('latin-1')))
                    conn.commit() 

            cookiehttp = scan.scan_httponly(cookie)
            if cookiehttp == True:
                request_have_bug = 1
                conn = get_db_connection()
                name = 'Cookie without HttpOnly flag set'
                bugurl = target["requesturl"]
                method = 'GET'
                cweid = 'CWE-16'
                confidence = 'Medium'
                risk = 'Medium'
                description = '''
If the HttpOnly attribute is set on a cookie, then the cookie's value cannot be read or set by client-side JavaScript. This measure makes certain client-side attacks, such as cross-site scripting, slightly harder to exploit by preventing them from trivially capturing the cookie's value via an injected script.
                '''
                solution = '''
There is usually no good reason not to set the HttpOnly flag on all cookies. Unless you specifically require legitimate client-side scripts within your application to read or set a cookie's value, you should set the HttpOnly flag by including this attribute within the relevant Set-cookie directive.

You should be aware that the restrictions imposed by the HttpOnly flag can potentially be circumvented in some circumstances, and that numerous other serious attacks can be delivered by client-side script injection, aside from simple cookie stealing.
                '''
                pentester = currentuser['username']
                reference = '''
https://portswigger.net/research/web-storage-the-lesser-evil-for-session-tokens#httponly
                '''
                duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
                if duplicate is None:
                    conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                                (id,
                                                name.encode('latin-1', 'replace').decode('latin-1'),
                                                bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                                method.encode('latin-1', 'replace').decode('latin-1'),
                                                cweid.encode('latin-1', 'replace').decode('latin-1'),
                                                confidence.encode('latin-1', 'replace').decode('latin-1'),
                                                description.encode('latin-1', 'replace').decode('latin-1'),
                                                solution.encode('latin-1', 'replace').decode('latin-1'),
                                                risk.encode('latin-1', 'replace').decode('latin-1'),
                                                reference.encode('latin-1', 'replace').decode('latin-1'),
                                                pentester.encode('latin-1', 'replace').decode('latin-1')))
                    conn.commit() 

        sqli = unau_sql_scan(target["requesturl"])
        if sqli == True:
            request_have_bug = 1
            conn = get_db_connection()
            name = 'SQL Injection'
            bugurl = target["requesturl"]
            method = 'GET'
            cweid = 'CWE-89'
            confidence = 'High'
            risk = 'High'
            description = "SQL injection, also known as SQLI, is a common attack vector that uses malicious SQL code for backend database manipulation to access information that was not intended to be displayed. This information may include any number of items, including sensitive company data, user lists or private customer details"
            solution = "The only sure way to prevent SQL Injection attacks is input validation and parametrized queries including prepared statements. The application code should never use the input directly. The developer must sanitize all input, not only web form inputs such as login forms. They must remove potential malicious code elements such as single quotes. It is also a good idea to turn off the visibility of database errors on your production sites. Database errors can be used with SQL Injection to gain information about your database"
            pentester = currentuser['username']
            reference = '''
https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
            '''
            duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
            if duplicate is None:
                conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            method.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            confidence.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1')))
                conn.commit()    

        lfi = unau_path_travel_scan(target["requesturl"],data["loginurl"],data["userparam"],data["passparam"],data["csrfparam"],data["username"],data["password"])
        if lfi == True:
            request_have_bug = 1
            conn = get_db_connection()
            name = 'Path Travelsal'
            bugurl = target["requesturl"]
            method = 'GET'
            cweid = 'CWE-98'
            confidence = 'High'
            risk = 'High'
            reference = '''
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion
            '''
            description = '''
A path traversal vulnerability allows an attacker to access files on your web server to which they should not have access. They do this by tricking either the web server or the web application running on it into returning files that exist outside of the web root folder
            '''
            solution = 'If possible, do not permit file paths to be appended directly. Make them hard-coded or selectable from a limited hard-coded path list via an index variableIf you definitely need dynamic path concatenation, ensure you only accept required characters such as "a-Z0-9" and do not allow ".." or "/" or "%00" (null byte) or any other similar unexpected characters.Its important to limit the API to allow inclusion only from a directory and directories below it. This ensures that any potential attack cannot perform a directory traversal attack.'
            pentester = currentuser['username']
            duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
            if duplicate is None:
                conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            method.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            confidence.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1')))
                conn.commit()

        xss = unau_rxss_scan(target["requesturl"],data["loginurl"],data["userparam"],data["passparam"],data["csrfparam"],data["username"],data["password"])
        if xss == True:
            request_have_bug = 1
            conn = get_db_connection()
            name = 'Cross-Site Scripting'
            bugurl = target["requesturl"]
            method = 'GET'
            cweid = 'CWE-79'
            confidence = 'High'
            risk = 'High'
            description = '''
Reflected XSS attacks, also known as non-persistent attacks, occur when a malicious script is reflected off of a web application to the victim's browser. The script is activated through a link, which sends a request to a website with a vulnerability that enables execution of malicious scripts.
            '''
            solution = '''
As with other injection attacks, careful input validation and context-sensitive encoding provide the first line of defense against reflected XSS. The “context-sensitive” part is where the real pitfalls are, because the details of safe encoding vary depending on where in the source code you are inserting the input data. For an in-depth discussion, see the OWASP Cross-Site Scripting Prevention Cheat Sheet and OWASP guide to Testing for Reflected Cross-Site Scripting.

Filtering inputs by blacklisting certain strings and characters is not an effective defense and is not recommended. This is why XSS filters are no longer used in modern browsers. For an in-depth defense against cross-site scripting and many other attacks, carefully configured Content-Security Policy (CSP) headers are the recommended approach.

The vast majority of cross-site scripting attempts, including non-persistent XSS, can be detected by a modern vulnerability testing solution. Invicti finds many types of XSS, from basic reflected XSS to more sophisticated attacks like DOM-based and blind XSS, and provides detailed recommendations about suitable remedies.
            '''
            pentester = currentuser['username']
            reference = '''
https://community.veracode.com/s/question/0D52T000053wYGwSAM/crosssite-scripting-xsscwe-id-80
            '''
            duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
            if duplicate is None:
                conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            method.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            confidence.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1')))
                conn.commit()
    if request_have_bug == 1:
        conn3 = get_db_connection()
        conn3.execute('UPDATE requests SET bug = ? WHERE requestid= ?',
                            ("Bug Found",id,)).fetchone()
        conn3.commit()
        conn3.close()
    if check["login"] == 1:
        data = conn.execute('SELECT * FROM sessions WHERE projectid = ?',(target["projectid"],)).fetchone()
        request_have_bug = 0
        scan = AuthenScanHeaders(target["requesturl"],data["loginurl"],data["userparam"],data["passparam"],data["csrfparam"],data["username"],data["password"])
        #X-XSS FOUND
        x_xss = scan.scan_xxss()
        if x_xss == True:
            request_have_bug = 1
            conn = get_db_connection()
            name = 'X-XSS-Protection Header is missing'
            bugurl = target["requesturl"]
            method = 'GET'
            cweid = 'CWE-693'
            confidence = 'Informational'
            risk = 'Informational'
            description = '''
Invicti detected a missing X-XSS-Protection header which means that this website could be at risk of a Cross-site Scripting (XSS) attacks.
            '''
            solution = '''
Add the X-XSS-Protection header with a value of "1; mode= block".
    X-XSS-Protection: 1; mode=block
Please also be advised that in some specific cases enabling XSS filter can be abused by attackers. However, in most cases, it provides basic protection for users against XSS attacks.
            '''
            pentester = currentuser['username']
            reference = '''
https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/missing-x-xss-protection-header/
            '''
            duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
            if duplicate is None:
                conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            method.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            confidence.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1')))
                conn.commit()  
        nosniff = scan.scan_nosniff()
        if nosniff == True:
            request_have_bug = 1
            conn = get_db_connection()
            name = 'X-Content-Type-Options Header is Missing'
            bugurl = target["requesturl"]
            method = 'GET'
            cweid = 'CWE-643'
            confidence = 'Low'
            risk = 'Low'
            description = '''
The Anti-MIME-Sniffing header X-Content-Type-Options was not set to ’nosniff’. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.
            '''
            solution = '''
Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages. If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.
            '''
            pentester = currentuser['username']
            reference = '''
https://www.iothreat.com/blog/x-content-type-options-header-missing#:~:text=The%20'X%2DContent%2DType,perform%20content%2Dtype%20sniffing%20attacks.
https://www.zaproxy.org/docs/alerts/10021/
http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx
            '''
            duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
            if duplicate is None:
                conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            method.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            confidence.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1')))
                conn.commit() 

        xframe = scan.scan_xframe()
        if xframe == True:
            request_have_bug = 1
            conn = get_db_connection()
            name = 'X-Frame-Options Header is Missing'
            bugurl = target["requesturl"]
            method = 'GET'
            cweid = 'CWE-613'
            confidence = 'Low'
            risk = 'Low'
            description = '''
The X-Frame-Options HTTP header field indicates a policy that specifies whether the browser should render the transmitted resource within a frame or an iframe. Servers can declare this policy in the header of their HTTP responses to prevent clickjacking attacks, which ensures that their content is not embedded into other pages or frames.
            '''
            solution = '''
Sending the proper X-Frame-Options in HTTP response headers that instruct the browser to not allow framing from other domains.
    X-Frame-Options: DENY  It completely denies to be loaded in frame/iframe.
    X-Frame-Options: SAMEORIGIN It allows only if the site which wants to load has a same origin.
    X-Frame-Options: ALLOW-FROM URL It grants a specific URL to load itself in a iframe. However please pay attention to that, not all browsers support this.
Employing defensive code in the UI to ensure that the current frame is the most top level window.
            '''
            pentester = currentuser['username']
            reference = '''
            https://www.iothreat.com/blog/x-content-type-options-header-missing#:~:text=The%20'X%2DContent%2DType,perform%20content%2Dtype%20sniffing%20attacks.
            '''
            duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
            if duplicate is None:
                conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            method.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            confidence.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1')))
                conn.commit()  

        hsts = scan.scan_hsts()
        if hsts == True:
            request_have_bug = 1
            conn = get_db_connection()
            name = 'Strict-Transport-Security Header is Missing'
            bugurl = target["requesturl"]
            method = 'GET'
            cweid = 'CWE-523'
            confidence = 'Medium'
            risk = 'Medium'
            description = '''
            The HTTP protocol by itself is clear text, meaning that any data that is transmitted via HTTP can be captured and the contents viewed. To keep data private and prevent it from being intercepted, HTTP is often tunnelled through either Secure Sockets Layer (SSL) or Transport Layer Security (TLS). When either of these encryption standards are used, it is referred to as HTTPS.

HTTP Strict Transport Security (HSTS) is an optional response header that can be configured on the server to instruct the browser to only communicate via HTTPS. This will be enforced by the browser even if the user requests a HTTP resource on the same server.

Cyber-criminals will often attempt to compromise sensitive information passed from the client to the server using HTTP. This can be conducted via various Man-in-The-Middle (MiTM) attacks or through network packet captures.

Scanner discovered that the affected application is using HTTPS however does not use the HSTS header.
            
            '''
            solution = '''
            Depending on the framework being used the implementation methods will vary, however it is advised that the `Strict-Transport-Security` header be configured on the server.
One of the options for this header is `max-age`, which is a representation (in milliseconds) determining the time in which the client's browser will adhere to the header policy.
Depending on the environment and the application this time period could be from as low as minutes to as long as days.
            
            '''
            pentester = currentuser['username']
            reference = '''
https://kinsta.com/knowledgebase/hsts-missing-from-https-server/#:~:text=Sometimes%2C%20an%20IT%20security%20scan,as%20a%20medium%2Drisk%20vulnerability.
https://www.ibm.com/support/pages/resolving-missing-hsts-or-missing-http-strict-transport-security-websphere
            '''
            duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
            if duplicate is None:
                conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            method.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            confidence.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1')))
                conn.commit()  

        policy = scan.scan_policy()
        if policy == True:
            request_have_bug = 1
            conn = get_db_connection()
            name = 'Content Security Policy (CSP) not implemented'
            bugurl = target["requesturl"]
            method = 'GET'
            cweid = 'CWE-523'
            confidence = 'Medium'
            risk = 'Medium'
            description = '''
Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks.

Content Security Policy (CSP) can be implemented by adding a Content-Security-Policy header. The value of this header is a string containing the policy directives describing your Content Security Policy. To implement CSP, you should define lists of allowed origins for the all of the types of resources that your site utilizes
            
            '''
            solution = '''
It's recommended to implement Content Security Policy (CSP) into your web application. Configuring Content Security Policy involves adding the Content-Security-Policy HTTP header to a web page and giving it values to control resources the user agent is allowed to load for that page.
            '''
            pentester = currentuser['username']
            reference = '''
https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
https://hacks.mozilla.org/2016/02/implementing-content-security-policy/
            '''
            duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
            if duplicate is None:
                conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            method.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            confidence.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1')))
                conn.commit()  

        cors = scan.scan_cors()
        if cors == True:
            request_have_bug = 1
            conn = get_db_connection()
            name = 'Content Security Policy (CSP) not implemented'
            bugurl = target["requesturl"]
            method = 'GET'
            cweid = 'CWE-523'
            confidence = 'Medium'
            risk = 'Medium'
            description = '''
CORS is a security feature created to selectively relax the SOP restrictions and enable controlled access to resources from different domains. CORS rules allow domains to specify which domains can request information from them by adding specific HTTP headers in the response. There are several HTTP headers related to CORS, but we are interested in the two related to the commonly seen vulnerabilities — Access-Control-Allow-Origin and Access-Control-Allow-Credentials. Access-Control-Allow-Origin: This header specifies the allowed domains to read the response contents. The value can be either a wildcard character (*), which indicates all domains are allowed, or a comma-separated list of domains.
            '''
            solution = '''
It’s primarily web server misconfigurations that enable CORS vulnerabilities. The solution is to prevent the vulnerabilities from arising in the first place by properly configuring your web server’s CORS policies
    1. Specify the allowed origins
    2. Only allow trusted sites
    3. Don’t whitelist “null”
    4. Implement proper server-side security policies
            '''
            pentester = currentuser['username']
            reference = '''
https://www.freecodecamp.org/news/exploiting-cors-guide-to-pentesting/
https://ranakhalil.teachable.com/p/web-security-academy-video-series
            '''
            duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
            if duplicate is None:
                conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            method.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            confidence.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1')))
                conn.commit() 

        server = scan.scan_server()
        if server == True:
            request_have_bug = 1
            conn = get_db_connection()
            name = "Server Leaks Information via 'X-Powered-By' HTTP Response Header Field(s)"
            bugurl = target["requesturl"]
            method = 'GET'
            cweid = 'CWE-200'
            confidence = 'Medium'
            risk = 'Medium'
            description = '''
The web/application server is leaking information via one or more “X-Powered-By” HTTP response headers. Access to such information may facilitate attackers identifying other frameworks/components your web application is reliant upon and the vulnerabilities such components may be subject to.
            '''
            solution = '''
Ensure that your web server, application server, load balancer, etc. is configured to suppress 'X-Powered-By' headers.
            '''
            pentester = currentuser['username']
            reference = '''
http://blogs.msdn.com/b/varunm/archive/2013/04/23/remove-unwanted-http-response-headers.aspx
http://www.troyhunt.com/2012/02/shhh-dont-let-your-response-headers.html
            '''
            duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
            if duplicate is None:
                conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            method.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            confidence.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1')))
                conn.commit() 

        for cookie in scan.cookies:
            cookiecure =scan.scan_secure(cookie)
            if cookiecure == True:
                request_have_bug = 1
                conn = get_db_connection()
                name = 'TLS cookie without secure flag set'
                bugurl = target["requesturl"]
                method = 'GET'
                cweid = 'CWE-614'
                confidence = 'Medium'
                risk = 'Medium'
                description = '''
If the secure flag is set on a cookie, then browsers will not submit the cookie in any requests that use an unencrypted HTTP connection, thereby preventing the cookie from being trivially intercepted by an attacker monitoring network traffic. If the secure flag is not set, then the cookie will be transmitted in clear-text if the user visits any HTTP URLs within the cookie's scope. An attacker may be able to induce this event by feeding a user suitable links, either directly or via another web site. Even if the domain that issued the cookie does not host any content that is accessed over HTTP, an attacker may be able to use links of the form http://example.com:443/ to perform the same attack.
                '''
                solution = '''
The secure flag should be set on all cookies that are used for transmitting sensitive data when accessing content over HTTPS. If cookies are used to transmit session tokens, then areas of the application that are accessed over HTTPS should employ their own session handling mechanism, and the session tokens used should never be transmitted over unencrypted communications.
                '''
                pentester = currentuser['username']
                reference = '''
https://owasp.org/www-community/controls/SecureCookieAttribute
                '''
                duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
                if duplicate is None:
                    conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                                (id,
                                                name.encode('latin-1', 'replace').decode('latin-1'),
                                                bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                                method.encode('latin-1', 'replace').decode('latin-1'),
                                                cweid.encode('latin-1', 'replace').decode('latin-1'),
                                                confidence.encode('latin-1', 'replace').decode('latin-1'),
                                                description.encode('latin-1', 'replace').decode('latin-1'),
                                                solution.encode('latin-1', 'replace').decode('latin-1'),
                                                risk.encode('latin-1', 'replace').decode('latin-1'),
                                                reference.encode('latin-1', 'replace').decode('latin-1'),
                                                pentester.encode('latin-1', 'replace').decode('latin-1')))
                    conn.commit() 

            cookiehttp = scan.scan_httponly(cookie)
            if cookiehttp == True:
                request_have_bug = 1
                conn = get_db_connection()
                name = 'Cookie without HttpOnly flag set'
                bugurl = target["requesturl"]
                method = 'GET'
                cweid = 'CWE-16'
                confidence = 'Medium'
                risk = 'Medium'
                description = '''
If the HttpOnly attribute is set on a cookie, then the cookie's value cannot be read or set by client-side JavaScript. This measure makes certain client-side attacks, such as cross-site scripting, slightly harder to exploit by preventing them from trivially capturing the cookie's value via an injected script.
                '''
                solution = '''
There is usually no good reason not to set the HttpOnly flag on all cookies. Unless you specifically require legitimate client-side scripts within your application to read or set a cookie's value, you should set the HttpOnly flag by including this attribute within the relevant Set-cookie directive.

You should be aware that the restrictions imposed by the HttpOnly flag can potentially be circumvented in some circumstances, and that numerous other serious attacks can be delivered by client-side script injection, aside from simple cookie stealing.
                '''
                pentester = currentuser['username']
                reference = '''
https://portswigger.net/research/web-storage-the-lesser-evil-for-session-tokens#httponly
                '''
                duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
                if duplicate is None:
                    conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                                (id,
                                                name.encode('latin-1', 'replace').decode('latin-1'),
                                                bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                                method.encode('latin-1', 'replace').decode('latin-1'),
                                                cweid.encode('latin-1', 'replace').decode('latin-1'),
                                                confidence.encode('latin-1', 'replace').decode('latin-1'),
                                                description.encode('latin-1', 'replace').decode('latin-1'),
                                                solution.encode('latin-1', 'replace').decode('latin-1'),
                                                risk.encode('latin-1', 'replace').decode('latin-1'),
                                                reference.encode('latin-1', 'replace').decode('latin-1'),
                                                pentester.encode('latin-1', 'replace').decode('latin-1')))
                    conn.commit() 

        sqli = au_sql_scan(target["requesturl"],data["loginurl"],data["userparam"],data["passparam"],data["csrfparam"],data["username"],data["password"])
        if sqli == True:
            request_have_bug = 1
            conn = get_db_connection()
            name = 'SQL Injection'
            bugurl = target["requesturl"]
            method = 'GET'
            cweid = 'CWE-89'
            confidence = 'High'
            risk = 'High'
            description = "SQL injection, also known as SQLI, is a common attack vector that uses malicious SQL code for backend database manipulation to access information that was not intended to be displayed. This information may include any number of items, including sensitive company data, user lists or private customer details"
            solution = "The only sure way to prevent SQL Injection attacks is input validation and parametrized queries including prepared statements. The application code should never use the input directly. The developer must sanitize all input, not only web form inputs such as login forms. They must remove potential malicious code elements such as single quotes. It is also a good idea to turn off the visibility of database errors on your production sites. Database errors can be used with SQL Injection to gain information about your database"
            pentester = currentuser['username']
            reference = '''
https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
            '''
            duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
            if duplicate is None:
                conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            method.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            confidence.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1')))
                conn.commit()    

        lfi = au_path_travel_scan(target["requesturl"],data["loginurl"],data["userparam"],data["passparam"],data["csrfparam"],data["username"],data["password"])
        if lfi == True:
            request_have_bug = 1
            conn = get_db_connection()
            name = 'Path Travelsal'
            bugurl = target["requesturl"]
            method = 'GET'
            cweid = 'CWE-98'
            confidence = 'High'
            risk = 'High'
            reference = '''
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion
            '''
            description = '''
A path traversal vulnerability allows an attacker to access files on your web server to which they should not have access. They do this by tricking either the web server or the web application running on it into returning files that exist outside of the web root folder
            '''
            solution = 'If possible, do not permit file paths to be appended directly. Make them hard-coded or selectable from a limited hard-coded path list via an index variableIf you definitely need dynamic path concatenation, ensure you only accept required characters such as "a-Z0-9" and do not allow ".." or "/" or "%00" (null byte) or any other similar unexpected characters.Its important to limit the API to allow inclusion only from a directory and directories below it. This ensures that any potential attack cannot perform a directory traversal attack.'
            pentester = currentuser['username']
            duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
            if duplicate is None:
                conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            method.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            confidence.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1')))
                conn.commit()

        xss = au_rxss_scan(target["requesturl"],data["loginurl"],data["userparam"],data["passparam"],data["csrfparam"],data["username"],data["password"])
        if xss == True:
            request_have_bug = 1
            conn = get_db_connection()
            name = 'Cross-Site Scripting'
            bugurl = target["requesturl"]
            method = 'GET'
            cweid = 'CWE-79'
            confidence = 'High'
            risk = 'High'
            description = '''
Reflected XSS attacks, also known as non-persistent attacks, occur when a malicious script is reflected off of a web application to the victim's browser. The script is activated through a link, which sends a request to a website with a vulnerability that enables execution of malicious scripts.
            '''
            solution = '''
As with other injection attacks, careful input validation and context-sensitive encoding provide the first line of defense against reflected XSS. The “context-sensitive” part is where the real pitfalls are, because the details of safe encoding vary depending on where in the source code you are inserting the input data. For an in-depth discussion, see the OWASP Cross-Site Scripting Prevention Cheat Sheet and OWASP guide to Testing for Reflected Cross-Site Scripting.

Filtering inputs by blacklisting certain strings and characters is not an effective defense and is not recommended. This is why XSS filters are no longer used in modern browsers. For an in-depth defense against cross-site scripting and many other attacks, carefully configured Content-Security Policy (CSP) headers are the recommended approach.

The vast majority of cross-site scripting attempts, including non-persistent XSS, can be detected by a modern vulnerability testing solution. Invicti finds many types of XSS, from basic reflected XSS to more sophisticated attacks like DOM-based and blind XSS, and provides detailed recommendations about suitable remedies.
            '''
            pentester = currentuser['username']
            reference = '''
https://community.veracode.com/s/question/0D52T000053wYGwSAM/crosssite-scripting-xsscwe-id-80
            '''
            duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
            if duplicate is None:
                conn.execute('INSERT INTO bugs (requestid,name,bugurl,method,cweid,confidence,description,solution,risk,reference,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            method.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            confidence.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1')))
                conn.commit()
    if request_have_bug == 1:
        conn3 = get_db_connection()
        conn3.execute('UPDATE requests SET bug = ? WHERE requestid= ?',
                            ("Bug Found",id,)).fetchone()
        conn3.commit()
        conn3.close()
    conn = get_db_connection()
    total_vunl = conn.execute('SELECT count(bugid) FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ?',(projectid,)).fetchone()
    conn.execute('UPDATE projects SET vunls=? WHERE projectid=?',
                        (total_vunl["count(bugid)"],projectid,))
    project = conn.execute('SELECT * FROM projects WHERE projectid = ?',(projectid,)).fetchone()
    requests = conn.execute('SELECT * FROM requests WHERE projectid = ?',(projectid,)).fetchall()
    users = conn.execute('SELECT * FROM users',).fetchall()
    total = conn.execute('SELECT count(requestid) FROM requests WHERE projectid = ?',(projectid,)).fetchone()
    totalrequest = total["count(requestid)"]
    done = conn.execute('SELECT count(requestid) FROM requests WHERE status = ? AND projectid = ?',("Done",projectid,)).fetchone()
    donerequest = done["count(requestid)"]
    remain = total["count(requestid)"] - done["count(requestid)"]
    conn.commit()
    bugs = conn.execute('SELECT bugs.name,count(bugid),risk FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ? GROUP BY bugs.name',(target["projectid"],)).fetchall()
    conn.commit()
    conn.close()
    return render_template('project_detail.html',bugs=bugs,currentuser=currentuser,users=users,project=project,totalrequest=totalrequest,donerequest=donerequest,remain=remain,requests=requests,msg=msg)
##########################################################################
########################## REPORT ########################################
##########################################################################
@app.route('/generate-report/<int:id>', methods=['GET'])
def download_report(id):
    conn = get_db_connection()
    currenuser = get_current_user()
    if session["userid"] == None:
        return redirect(url_for('login'))
    results = conn.execute('SELECT * FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ?',(id,)).fetchall()
    project = conn.execute('SELECT * FROM projects WHERE projectid = ?',(id,)).fetchone()
    total_vunl = conn.execute('SELECT count(bugid) FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ?',(id,)).fetchone()
    summarys = conn.execute('SELECT count(requests.requestid),count(bugid),name,bugurl,risk,method,confidence,cweid,description,solution,reference,other,requesturl FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ? GROUP BY name',(id,)).fetchall()
    securitilevel =''
    for result in results:
        if result['risk'] == "Infomational":
            securitilevel = result['risk']
    for result in results:
        if result['risk'] == "Low":
            securitilevel = result['risk']
    for result in results:
        if result['risk'] == "Medium":
            securitilevel = result['risk']
    for result in results:
        if result['risk'] == "High":
            securitilevel = result['risk']
    for result in results:
        if result['risk'] == "Critical":
            securitilevel = result['risk']

    pdf = FPDF()
    pdf.add_page()
    
    page_width = pdf.w - 2 * pdf.l_margin
    pdf.set_font('Times','B',14.0)
    pdf.cell(page_width, 0.0,' FINAL REPORT', align='C')
    pdf.ln(10)
    pdf.cell(page_width, 0.0, "I. Document Properties")
    pdf.ln(5)
    pdf.set_font('Times','B',13.0)
    pdf.cell(page_width, 0.0, "1. Scope of work")
    pdf.ln(5)
    pdf.set_font('Times','',12.0)
    th = pdf.font_size
    pdf.cell(page_width, th, "The scope of the penetration test was limited to the following target:")
    pdf.ln(5)
    th = pdf.font_size
    pdf.cell(page_width/3, th, 'Target ',border = 1)
    pdf.cell(page_width/1.5, th, project["target"],border = 1)
    pdf.ln(10)
    pdf.set_font('Times','B',13.0)
    pdf.cell(page_width, 0.0, "2. Executive Summary")
    pdf.ln(5)
    pdf.set_font('Times','',12.0)
    th = pdf.font_size
    pdf.cell(page_width, th, "The information of project is listed bellow:")
    pdf.ln(5)
    pdf.set_font('Times', '', 12)
    th = pdf.font_size
    # project info

    pdf.cell(page_width/3, th, 'Project Name ',border = 1)
    pdf.cell(page_width/1.5, th, project["projectname"],border = 1)
    pdf.ln(5)
    pdf.cell(page_width/3, th, 'Start Date ',border = 1)
    pdf.cell(page_width/1.5, th, str(project["startdate"]),border = 1)
    pdf.ln(5)
    pdf.cell(page_width/3, th, 'End Date ',border = 1)
    pdf.cell(page_width/1.5, th, str(project["enddate"]),border = 1)
    pdf.ln(5)
    pdf.cell(page_width/3, th, 'Project Manager ',border = 1)
    pdf.cell(page_width/1.5, th, project["manager"],border = 1)
    pdf.ln(5)
    pdf.cell(page_width/3, th, 'Project Penteser ',border = 1)
    pdf.cell(page_width/1.5, th,project["pentester"],border = 1)
    pdf.ln(5)
    pdf.cell(page_width/3, th, 'Total Vulnerabilities',border = 1)
    pdf.cell(page_width/1.5, th,str(total_vunl["count(bugid)"]),border = 1)
    pdf.ln(5)
    pdf.cell(page_width/3, th, 'Risk Level',border = 1)
    pdf.cell(page_width/1.5, th,securitilevel,border = 1)
    pdf.ln(5)
    
        
    pdf.set_font('Times','B',13.0)
    pdf.ln(10)
    pdf.cell(page_width, 0.0, "3. Summary of Findings")
    pdf.ln(5)
    pdf.set_font('Times','',12.0)
    th = pdf.font_size
    pdf.cell(page_width, th, "After performing the test on the target, we give the following summary results : ")
    pdf.ln(5)
    pdf.set_font('Times', '', 12)
    th = pdf.font_size
    
    pdf.set_font('Times', '', 12)
    th = pdf.font_size
    col_width = page_width/4
		
    pdf.ln(1)
		
    i = 1
    pdf.cell(page_width/13, th, "Index",border = 1,align='C')
    pdf.cell(page_width/1.4, th, "Bug name",border = 1,align='C')
    pdf.cell(page_width/7, th,'Risk',border = 1,align='C')
    pdf.cell(page_width/15, th,"Count",border = 1,align='C')
    pdf.ln(th)
    for row in summarys:
        pdf.cell(page_width/13, th, str(i),border = 1,align='C')
        pdf.cell(page_width/1.4, th, row['name'],border = 1)
        pdf.cell(page_width/7, th,row['risk'],border = 1)
        pdf.cell(page_width/15, th,str(row['count(bugid)']),border = 1,align='C')
        pdf.ln(th)
        i = i+1
    pdf.ln(10)        
    pdf.set_font('Times','B',14.0)
    pdf.cell(page_width, 0.0, "II. Bugs Detail")
    pdf.ln(5)
    k = 1
    w=0
    pdf.set_font('Times','',13.0)
    
    for row in summarys:
        pdf.set_font('Times','B',13.0)
        pdf.cell(page_width/20, th, str(k)+".",'C')
        pdf.cell(page_width/1.2, th, row['name'])
        pdf.ln(th)
        
        pdf.set_font('Times','B',13.0)
        pdf.cell(page_width/5, th, "Totail Enpoint : ")
        pdf.set_font('Times','',13.0)
        pdf.cell(page_width/4, th, str(row['count(requests.requestid)']))
        pdf.ln(th)
        
        pdf.set_font('Times','B',13.0)
        pdf.cell(page_width/5, th, "Cweid: ")
        pdf.set_font('Times','',13.0)
        pdf.cell(page_width/4, th, str(row['cweid']))
        pdf.ln(th)
        
        pdf.set_font('Times','B',13.0)
        pdf.cell(page_width/5, th, "Risk: ")
        pdf.set_font('Times','',13.0)
        pdf.cell(page_width/5, th, row['risk'])
        pdf.ln(th)
        pdf.set_font('Times','B',13.0)
        pdf.cell(page_width/5, th, "Enpoint: ")
        pdf.ln(th)
        conn = get_db_connection()
        bugurls = conn.execute('SELECT method,bugurl FROM bugs,requests WHERE requests.requestid = bugs.requestid AND projectid = ? AND bugs.name = ?',(id,row['name'],)).fetchall()
        pdf.set_font('Times','',13.0)
        for bugurl in bugurls:
            pdf.cell(page_width/50, th, '- ')
            pdf.multi_cell(0, th, bugurl['method'])
            pdf.multi_cell(0, th, bugurl["bugurl"])
            pdf.ln(th)
        pdf.ln(th)
        
        pdf.set_font('Times','B',13.0)
        pdf.cell(page_width/20, th, "Description: ")
        pdf.set_font('Times','',13.0)
        pdf.ln(th)
        pdf.multi_cell(0, th, str(row['description']))
        pdf.ln(th)
        
        pdf.set_font('Times','B',13.0)
        pdf.cell(page_width/20, th, "Solution : ")
        pdf.ln(th)
        pdf.set_font('Times','',13.0)
        pdf.multi_cell(0, th, row['solution'])
        pdf.ln(th)
        
        pdf.set_font('Times','B',13.0)
        pdf.cell(page_width/20, th, "Reference: ")
        pdf.ln(th)
        pdf.set_font('Times','',13.0)
        pdf.multi_cell(0, th, row['reference'])
        pdf.ln(th)
        
        pdf.set_font('Times','B',13.0)
        pdf.cell(0, th, "Other: ")
        pdf.ln(th)
        pdf.set_font('Times','',13.0)
        pdf.multi_cell(0, th, row['other'])
        pdf.ln(th)
        k = k + 1
    pdf.ln(10)
    pdf.set_font('Times','',10.0) 
    pdf.cell(page_width, 0.0, '- end of report -', align='C')
    return Response(pdf.output(dest='S').encode('latin-1'), mimetype='application/pdf', headers={'Content-Disposition':'attachment;filename=final_report.pdf'})
if __name__ == '__main__':
    app.run(debug=True)