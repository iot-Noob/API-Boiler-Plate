import sqlite3
from fastapi import HTTPException
import dotenv
import os
from App.GetEnvDate import db_path,db_name

if not os.path.exists(db_path) and db_path:
    os.mkdir(db_path)

async def RunQuery(
    q: str, val: tuple, fetch_om: str = "ONE", exec_om: bool = False
) -> tuple:
    try:
        # Establish the database connection\
        if db_name and db_path:
            ffp=os.path.join(db_path,db_name)
            con = sqlite3.connect(ffp)

        elif db_name:
            con = sqlite3.connect(str(db_name))
        elif not db_path and not db_name or not db_name or not db_path:
            con = sqlite3.connect("databases.db")
        else:
            return HTTPException(400,"No db path define for sqlite")
        cur = con.cursor()

        if exec_om:
            cur.executemany(q, val)
        else:
            cur.execute(q, val)

        result = None
        match fetch_om:
            case "ALL":
                result = cur.fetchall()
            case "MANY":
                result = cur.fetchmany()
            case "ONE":
                result = cur.fetchone()
            case _:
                raise ValueError("Invalid fetch_om value")

        con.commit()
        return result

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error occurred during query execution: {e}"
        )

    finally:
        cur.close()
        con.close()
