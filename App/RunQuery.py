import sqlite3
from fastapi import HTTPException 
import os
from App.CreateDatabase import  DatabaseManager

 
db=DatabaseManager()
 
async def RunQuery(
    q: str, val: tuple, fetch_om: str = "ONE", exec_om: bool = False
) -> tuple:
    
    try: 
        db.connect_db()
        connect=db.get_connect()
        cursor=db.get_cursor()
      
        result = None
        match fetch_om:
            case "ALL":
                result = cursor.fetchall()
            case "MANY":
                result = cursor.fetchmany()
            case "ONE":
                result = cursor.fetchone()
            case _:
                raise ValueError("Invalid fetch_om value")

        connect.commit()
        return result

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error occurred during query execution: {e}"
        )

    finally:
        db.close_connection()
        # cursor.close()
        # connect.close()