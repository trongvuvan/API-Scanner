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

from src.security import zapspider,zapactivescan 
app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
apiKey = 'k7mjaq5qv8ignhr62m89me71t'

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
@app.route('/login', methods=['GET', 'POST'])
def login():
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
            return redirect(url_for('index'))
        else:
            msg = 'Username or password is incorrect'
            return render_template('login.html',msg=msg)
    return render_template('login.html')
@app.route("/myprofile")
def profile():
    msg =''
    if session["userid"] == None:
        return redirect(url_for('login'))
    cur = get_db_connection()
    userid = session["userid"]
    user = cur.execute('SELECT * FROM users WHERE userid = ?',(userid,)).fetchall()
    cur.commit()
    cur.close()
    if user is not None:
        return render_template('profile.html',user=user,msg=msg)
    else:
        return 'user not exist'
@app.route('/add-user', methods=('GET', 'POST'))
def add_user():
    currentuser = get_current_user()
    if currentuser["role"] != 'Administrator':
        return render_template('403.html',)
    if session["userid"] == None:
        return redirect(url_for('login'))
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
    return render_template('add_user.html',msg=msg)
@app.route("/search_user", methods=['GET', 'POST'])
def search_user():
    currentuser = get_current_user()
    if currentuser["role"] != 'Administrator':
        return render_template('403.html',)
    if session["userid"] == None:
        return redirect(url_for('login'))
    msg = ''
    if request.method == 'GET':
        username = request.args.get('username')
        conn = get_db_connection()
        users = conn.execute('SELECT * FROM users WHERE username like ?',(username,)).fetchall()
        conn.commit()
        conn.close()
        if users is not None:
            return render_template('show_user.html', users = users ,msg = msg)
        else: 
            msg = 'User not found'
            return render_template('show_user.html', users = users ,msg = msg)
        
@app.route("/change-pass", methods=['GET', 'POST'])
def changepwd():
    msg = ''
    if session["userid"] == None:
        return redirect(url_for('login'))
    if request.method == 'POST':
        currentuser = get_current_user()
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
        return render_template('profile.html',user=user,msg = msg)
    return render_template('changes_pass.html', msg = msg)
@app.route("/about-us")
def about_us():
    return render_template('about_us.html')
@app.route("/logout")
def logout():
    session["userid"] = None
    return redirect(url_for('index'))
@app.route("/")
def index():
    return render_template('index.html')
@app.route("/enableaccount", methods=('GET', 'POST'))
def enableaccount():
    currentuser = get_current_user()
    if currentuser["role"] != 'Administrator':
        return render_template('403.html',)
    msg = ''
    if session["userid"] == None:
        return redirect(url_for('login'))
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
    return render_template('show_user.html', users=users,msg=msg)
    return render_template('index.html')
@app.route('/usermanager', methods=('GET', 'POST'))
def showuser():
    currentuser = get_current_user()
    if currentuser["role"] != 'Administrator':
        return render_template('403.html',)
    msg = ''
    if session["userid"] == None:
        return redirect(url_for('login'))
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
    return render_template('show_user.html', users=users,msg=msg)

@app.route('/edituser/<int:id>', methods=('GET', 'POST'))
def edituser(id):
    currentuser = get_current_user()
    if currentuser["role"] != 'Administrator':
        return render_template('403.html',)
    msg=''
    currentuser = get_current_user()
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
                    return render_template('show_user.html', users=users,msg=msg)
        return render_template('edit_user.html', update=update,msg=msg)
        
@app.route('/projectmanager', methods=('GET', 'POST'))
def showproject():
    msg = ''
    if session["userid"] == None:
        return redirect(url_for('login'))
    if request.method == 'POST':
        currentuser = get_current_user()
        if currentuser["role"] == 'Pentester':
            return render_template('403.html',)
        conn = get_db_connection()
        projectid = request.form['projectid']
        exist = conn.execute('DELETE FROM projects WHERE projectid = ?',(projectid,)).fetchone()
        conn.commit()
        conn.close()
        msg = ''
        if exist is None:
            msg ='Delete sucessfully'
        else:
            msg = 'An error occurred while deleting'
    conn = get_db_connection()
    projects = conn.execute('SELECT * FROM projects').fetchall()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.commit()
    conn.close()
    return render_template('show_project.html', projects=projects,users=users,msg=msg)
@app.route('/editproject/<int:id>', methods=('GET', 'POST'))
def editproject(id):
    msg = ''
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    if currentuser["role"] == 'Pentester':
        return render_template('403.html',)
    conn = get_db_connection()
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
    
    return render_template('edit_project.html', projects=projects,users=users,msg=msg)
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
        loginrequired = request.form['loginrequired']
        if loginrequired == 0:
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
                conn.close()
                return redirect(url_for('showproject'))
        else:
            status = 'Pending'
            userinfo = request.form['userinfo']
            passinfo = request.form['passinfo']
            exist = conn.execute('SELECT * FROM projects WHERE projectname = ?',(projectname,)).fetchone()
            if exist is not None:
                msg = 'Project Name already existed'
                return render_template('add_project.html',users=users,msg=msg)
            else:
                msg = 'Create Project successfully'
                conn = get_db_connection()
                conn.execute("INSERT INTO projects (projectname,startdate,target,create_by,manager,pentester,status,login,userinfo,passinfo) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (projectname,startdate,target,currentuser["username"],manager,pentester,status,loginrequired,userinfo,passinfo))
                conn.commit()
                conn.close()
                return redirect(url_for('showproject'))
    return render_template('add_project.html',users=users,msg=msg)
@app.route("/search_project", methods=['GET', 'POST'])
def search_project():
    if session["userid"] == None:
        return redirect(url_for('login'))
    msg = ''
    if request.method == 'GET':
        projectname = request.args.get('projectname')
        conn = get_db_connection()
        projects = conn.execute('SELECT * FROM projects WHERE projectname like ?',(projectname,)).fetchall()
        users = conn.execute('SELECT * FROM users').fetchall()
        conn.commit()
        conn.close()
        if projects is not None:
            return render_template('show_project.html', projects = projects,users=users ,msg = msg)
        else: 
            msg = 'Project not found'
            return render_template('show_project.html', projects = projects,users=users,msg = msg)
@app.route('/project-detail/<int:id>', methods=('GET', 'POST'))
def project_detail(id):
    msg = ''
    conn = get_db_connection()
    if session["userid"] == None:
        return redirect(url_for('login'))
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users',).fetchall()
    havebugs = conn.execute('SELECT * FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ? AND bugs.requestid in (SELECT requestid FROM bugs) GROUP BY bugs.requestid',(id,)).fetchall()
    project = conn.execute('SELECT * FROM projects WHERE projectid = ?',(id,)).fetchone()
    requests = conn.execute('SELECT * FROM requests WHERE projectid = ?',(id,)).fetchall()
    total = conn.execute('SELECT count(requestid) FROM requests WHERE projectid = ?',(id,)).fetchone()
    totalrequest = total["count(requestid)"]
    done = conn.execute('SELECT count(requestid) FROM requests WHERE status = ? AND projectid = ?',("done",id,)).fetchone()
    donerequest = done["count(requestid)"]
    remain = total["count(requestid)"] - done["count(requestid)"]
    conn.commit()
    conn.close()
    return render_template('project_detail.html',havebugs=havebugs,users=users,project=project,totalrequest=totalrequest,donerequest=donerequest,remain=remain,requests=requests,msg=msg)
@app.route('/bug-detail/<int:id>', methods=('GET', 'POST'))
def bug_detail(id):
    # id = requestid
    msg = ''
    conn = get_db_connection()
    if session["userid"] == None:
        return redirect(url_for('login'))
    conn = get_db_connection()
    bugs = total = conn.execute('SELECT * FROM bugs WHERE requestid = ?',(id,)).fetchall()
    return render_template('bug_detail.html',bugs=bugs,msg=msg)
## SECURITY
@app.route('/spider-scan/<int:id>', methods=('GET', 'POST'))
def spiderscan(id):
    msg = ''
    conn = get_db_connection()
    target = conn.execute('SELECT * FROM projects WHERE projectid = ?',(id,)).fetchone()
    conn.commit()
    conn.close()
    results = zapspider(target["target"])
    isspider = 1
    conn = get_db_connection()
    conn.execute('UPDATE projects SET isspider=?,status=? WHERE projectid=?',
                        (isspider,"Doing",id,)).fetchone()
    conn.commit()
    for result in results:
        if result is not None:
            status = 'Pending'
            isscan = 0
            conn = get_db_connection()
            conn.execute('INSERT INTO requests (projectid,requesturl,status,isscan) VALUES (?,?,?,?)',
                                (id,result,status,isscan,))
            conn.commit()
    projects = conn.execute('SELECT * FROM projects').fetchall()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.commit()
    conn.close()
    return render_template('show_project.html', projects=projects,users=users,msg=msg)
@app.route('/activescan/<int:id>', methods=('GET', 'POST'))
def activescan(id):
    msg = ''
    currenuser = get_current_user()
    conn = get_db_connection()
    target = conn.execute('SELECT * FROM requests WHERE requestid = ?',(id,)).fetchone()
    conn.commit()
    conn.close()
    projectid = target["projectid"]
    requesturl = target["requesturl"]
    scanresults = zapactivescan(requesturl)
    conn = get_db_connection()
    isscan = 1
    conn.execute('UPDATE requests SET isscan=?,status = ?,pentester=? WHERE requestid=?',
                        (isscan,"done",currenuser["username"],id,)).fetchone()
    conn.commit()
    for scanresult in scanresults:
        conn = get_db_connection()
        conn.execute('INSERT INTO bugs (requestid,name,method,cweid,confidence,description,solution,risk,reference,other,pentester) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                            (id,scanresult["alert"],scanresult["method"],scanresult["cweid"],scanresult["confidence"],
                             scanresult["description"],scanresult["solution"],scanresult["risk"],scanresult["reference"],
                             scanresult["other"],currenuser["username"],))
        conn.execute('UPDATE requests SET bug=? WHERE requestid=?',
                        ("Bug Found",id,)).fetchone()
        conn.commit()
    conn = get_db_connection()
    project = conn.execute('SELECT * FROM projects WHERE projectid = ?',(projectid,)).fetchone()
    requests = conn.execute('SELECT * FROM requests WHERE projectid = ?',(projectid,)).fetchall()
    users = conn.execute('SELECT * FROM users',).fetchall()
    total = conn.execute('SELECT count(requestid) FROM requests WHERE projectid = ?',(projectid,)).fetchone()
    totalrequest = total["count(requestid)"]
    done = conn.execute('SELECT count(requestid) FROM requests WHERE status = ? AND projectid = ?',("done",projectid,)).fetchone()
    donerequest = done["count(requestid)"]
    remain = total["count(requestid)"] - done["count(requestid)"]
    conn.commit()
    conn.close()
    return render_template('project_detail.html',users=users,project=project,totalrequest=totalrequest,donerequest=donerequest,remain=remain,requests=requests,msg=msg)
# report FUNCTIONS
@app.route('/generate-report/<int:id>', methods=['GET'])
def download_report(id):
    conn = get_db_connection()
    currenuser = get_current_user()
    if session["userid"] == None:
        return redirect(url_for('login'))
    results = conn.execute('SELECT * FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ?',(id,)).fetchall()
    project = conn.execute('SELECT * FROM projects WHERE projectid = ?',(id,)).fetchone()
    total_vunl = conn.execute('SELECT count(bugid) FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ?',(id,)).fetchone()
    
    for result in results:
        if result['risk'] == "Infomation":
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
    pdf.cell(page_width, 0.0, "1.1 Scope of work")
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
    pdf.cell(page_width, 0.0, "1.2 Executive Summary")
    pdf.ln(5)
    pdf.set_font('Times', '', 12)
    th = pdf.font_size
    # project info

    pdf.cell(page_width/3, th, 'Project Name ',border = 1)
    pdf.cell(page_width/1.5, th, project["projectname"],border = 1)
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
    pdf.cell(page_width, 0.0, "1.3 Summary of Findings")
    pdf.ln(5)
    pdf.set_font('Times', '', 12)
    th = pdf.font_size
    
    pdf.set_font('Times', '', 12)
    th = pdf.font_size
    col_width = page_width/4
		
    pdf.ln(1)
		
    i = 1
    pdf.cell(page_width/15, th, "Index",border = 1)
    pdf.cell(page_width/1.5, th, "Bug name",border = 1)
    pdf.cell(page_width/8, th,'Method',border = 1)
    pdf.cell(page_width/5.5, th,"Risk",border = 1)
    pdf.ln(th)
    for row in results:
        pdf.cell(page_width/15, th, str(i),border = 1)
        pdf.cell(page_width/1.5, th, str(row['name']),border = 1)
        pdf.cell(page_width/8, th,row['method'],border = 1)
        pdf.cell(page_width/5.5, th,row['risk'],border = 1)
        pdf.ln(th)
        i = i+1
    pdf.ln(10)        
    pdf.set_font('Times','B',13.0)
    pdf.cell(page_width, 0.0, "II. Bugs Detail")
    pdf.ln(5)
          
          
    pdf.ln(10)
    pdf.set_font('Times','',10.0) 
    pdf.cell(page_width, 0.0, '- end of report -', align='C')
    return Response(pdf.output(dest='S').encode('latin-1'), mimetype='application/pdf', headers={'Content-Disposition':'attachment;filename=final_report.pdf'})
if __name__ == '__main__':
    app.run(debug=True)