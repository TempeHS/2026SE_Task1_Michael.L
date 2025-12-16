"""
User Management module for Devloper Logs Application

This application handles all database operations for user authentication and developer
log management.
"""

import sqlite3 as sql
import bcrypt


def getLogs(filter_by_dev=None, start_date=None, end_date=None, project=None):
    con = sql.connect("databaseFiles/database.db")
    try:
        con.row_factory = sql.Row
        cur = con.cursor()
        query = "SELECT id, developer, project, repo, start_time, end_time, log_entry_time, time_worked, developer_notes, created_by FROM logs WHERE 1=1"
        parameters = []
        if filter_by_dev:
            query += " AND developer = ?"
            parameters.append(filter_by_dev)
        if start_date:
            query += " AND DATE(log_entry_time) >= DATE(?)"
            parameters.append(start_date)
        if end_date:
            query += " AND DATE(log_entry_time) <= DATE(?)"
            parameters.append(end_date)
        if project:
            query += " AND project = ?"
            parameters.append(project)
        query += " ORDER BY log_entry_time DESC"
        cur.execute(query, parameters)
        headings = cur.fetchall()
        return [dict(row) for row in headings]
    except Exception as e:
        print(f"Database error in getting logs: {e}")
        return []
    finally:
        con.close()


def getLogByID(log_id):
    con = sql.connect("databaseFiles/database.db")
    try:
        con.row_factory = sql.Row
        cur = con.cursor()
        cur.execute(
            "SELECT id, developer, project, repo, start_time, end_time, log_entry_time, time_worked, developer_notes, created_by From logs WHERE id = ?",
            (log_id,),
        )
        headings = cur.fetchone()
        return dict(headings) if headings else None
    except Exception as e:
        print(f"Database error in getting logs: {e}")
        return None
    finally:
        con.close()


def get_all_devs():
    con = sql.connect("databaseFiles/database.db")
    try:
        cur = con.cursor()
        cur.execute("SELECT DISTINCT developer FROM logs ORDER BY developer ASC")
        headings = cur.fetchall()
        return [row[0] for row in headings]
    except Exception as e:
        print(f"Database error in getting devs: {e}")
        return []
    finally:
        con.close()


def get_all_projects():
    con = sql.connect("databaseFiles/database.db")
    try:
        cur = con.cursor()
        cur.execute("SELECT DISTINCT project FROM logs ORDER BY project ASC")
        headings = cur.fetchall()
        return [row[0] for row in headings]
    except Exception as e:
        print(f"Database error in getting projects: {e}")
        return []
    finally:
        con.close()


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
    created_by,
):
    con = sql.connect("databaseFiles/database.db")
    try:
        cur = con.cursor()
        cur.execute(
            "INSERT INTO logs (developer, project, repo, start_time, end_time, log_entry_time, time_worked, developer_notes, created_by) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                developer,
                project,
                repo,
                start_time,
                end_time,
                log_entry_time,
                time_worked,
                developer_notes,
                created_by,
            ),
        )
        con.commit()
    except sql.IntegrityError:
        con.rollback()
        return False
    finally:
        con.close()
    return True


def deleteLog(log_id):
    con = sql.connect("databaseFiles/database.db")
    try:
        cur = con.cursor()
        cur.execute("DELETE FROM logs WHERE id = ?", (log_id,))
        con.commit()
        return True
    except Exception as e:
        print(f"Database error in deleting logs: {e}")
        con.rollback()
        return False
    finally:
        con.close()


def updatelog(
    log_id,
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
            "UPDATE logs SET developer = ?, project = ?, repo = ?, start_time = ?, end_time = ?, log_entry_time = ?, time_worked = ?, developer_notes = ? WHERE id = ?",
            (
                developer,
                project,
                repo,
                start_time,
                end_time,
                log_entry_time,
                time_worked,
                developer_notes,
                log_id,
            ),
        )
        con.commit()
        return True
    except Exception as e:
        print(f"Database error in updating logs: {e}")
        con.rollback()
        return False
    finally:
        con.close()
