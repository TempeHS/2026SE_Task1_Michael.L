import sqlite3 as sql
import bcrypt


### example
def getUsers():
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM UserInfo").fetchall()
    con.close()
    return cur


def insertUser(email, password):
    con = sql.connect("databaseFiles/database.db")
    try:
        cur = con.cursor()
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        cur.execute(
            "INSERT INTO UserInfo (email,password) VALUES (?,?)",
            (email, hashed.decode("utf-8")),
        )
        con.commit()
    except sql.IntegrityError:
        con.rollback()
        return False
    finally:
        con.close()
    return True


def VerifyUser(email, password):
    con = sql.connect("databaseFiles/database.db")
    try:
        cur = con.cursor()
        cur.execute("SELECT password FROM UserInfo WHERE email = ?", (email,))
        output = cur.fetchone()
        if output is None:
            return False
        hashed_P = output[0]
        return bcrypt.checkpw(password.encode("utf-8"), hashed_P.encode("utf-8"))
    except Exception as e:
        return False
    finally:
        con.close()


def insertLogs(
    developer,
    project,
    repo,
    start_time,
    end_time,
    log_entry_time,
    time_worked,
    developer_notes,
):
    con = sql.connect("databaseFiles/database.db")
    try:
        cur = con.cursor()
        cur.execute(
            "INSERT INTO logs (developer, project, repo, start_time, end_time, log_entry_time, time_worked, developer_notes) VALUES (?,?,?,?,?,?,?,?)",
            (
                developer,
                project,
                repo,
                start_time,
                end_time,
                log_entry_time,
                time_worked,
                developer_notes,
            ),
        )
        con.commit()
    except sql.IntegrityError:
        con.rollback()
        return False
    finally:
        con.close()
    return True


def getlogs(): ...
