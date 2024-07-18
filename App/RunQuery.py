import sqlite3
from fastapi import HTTPException
import dotenv
import os

dotenv.load_dotenv()
dbpath = os.getenv("DB_PATH")


async def RunQuery(
    q: str, val: tuple, fetch_om: str = "ONE", exec_om: bool = False
) -> tuple:
    try:
        # Establish the database connection
        if not dbpath:
            con = sqlite3.connect("vid_conv_data.db")
        else:
            con = sqlite3.connect(dbpath)
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
