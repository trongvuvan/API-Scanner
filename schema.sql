DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS requests;
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
    manager INTEGER NOT NULL,
    pentester INTEGER NOT NULL,
    status TEXT NOT NULL,
    create_by INTEGER NOT NULL,
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
    bug TEXT ,
    isscan INTEGER ,
    pentester TEXT ,
    FOREIGN KEY (pentester) REFERENCES users(userid) ON DELETE CASCADE
    FOREIGN KEY (projectid) REFERENCES projects(projectid) ON DELETE CASCADE
);
