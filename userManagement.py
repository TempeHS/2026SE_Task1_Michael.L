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

        # hash stuff here

        cur.execute(
            "INSERT INTO UserInfo (email,password) VALUES (?,?)", (email, password)
        )
        con.commit()
    except sql.IntegrityError:
        con.rollback()
        return False
    finally:
        con.close()
    return True
