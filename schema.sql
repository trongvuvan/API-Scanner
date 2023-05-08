DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS requests;
DROP TABLE IF EXISTS bugs;
CREATE TABLE users (
    userid INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    join_date date NOT NULL,
    update_date date,
    create_by TEXT NOT NULL,
    update_by TEXT,
    role TEXT NOT NULL
);
CREATE TABLE projects (
    projectid INTEGER PRIMARY KEY AUTOINCREMENT,
    projectname TEXT NOT NULL,
    startdate date NOT NULL,
    enddate date,
    vunls int,
    target text not null,
    securitylevel TEXT,
    manager INTEGER ,
    pentester INTEGER ,
    status TEXT NOT NULL,
    create_by INTEGER ,
    isspider TEXT,
    FOREIGN KEY (pentester) REFERENCES users(userid) ON DELETE CASCADE
    FOREIGN KEY (manager) REFERENCES users(userid) ON DELETE CASCADE
    FOREIGN KEY (create_by) REFERENCES users(userid) ON DELETE CASCADE
);
CREATE TABLE requests (
    requestid INTEGER PRIMARY KEY AUTOINCREMENT,
    projectid INTEGER NOT NULL,
    requesturl TEXT NOT NULL,
    status TEXT NOT NULL,
    bug TEXT,
    isscan INTEGER ,
    pentester INTEGER ,
    FOREIGN KEY (pentester) REFERENCES users(userid) ON DELETE CASCADE
    FOREIGN KEY (projectid) REFERENCES projects(projectid) ON DELETE CASCADE
);
CREATE TABLE bugs (
    bugid INTEGER PRIMARY KEY AUTOINCREMENT,
    requestid INTEGER NOT NULL,
    name TEXT NOT NULL,
    method TEXT NOT NULL,
    cweid TEXT NOT NULL,
    confidence TEXT NOT NULL,
    description TEXT NOT NULL,
    solution TEXT NOT NULL,
    risk TEXT NOT NULL,
    reference TEXT NOT NULL,
    other TEXT NOT NULL,
    pentester INTEGER,
    FOREIGN KEY (pentester) REFERENCES users(userid) ON DELETE CASCADE
    FOREIGN KEY (requestid) REFERENCES requests(requestid) ON DELETE CASCADE
);
