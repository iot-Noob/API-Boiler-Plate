from App.RunQuery import RunQuery
from fastapi import HTTPException
from App.LoggingInit import *
from typing import Optional
async def Delete_user():
    try:
        du = await RunQuery(q="""DROP TABLE IF EXISTS users""", val=())
        return {"Delete user table success": du if du else ""}
    except Exception as e:
        raise HTTPException(500, f"Error cannot delete user due to: {e}")


 


async def delete_all():
 
    await Delete_user()
 
 


 
##Delete  records for table.

async def delete_user(token: str | None = None, id: int | None = None):
    try:
        if id:
            tid = id
        if token:
            tid = token["id"]
        dqfs = await RunQuery(
            q="""
               DELETE FROM users WHERE id==?;
              """,
            val=(tid,),
        )
        logging.info(f"delete all user records ")
        return {"Delete all record for": token["username"], "status": f"sucess {dqfs if dqfs else ""}"}
    except Exception as e:
        logging.error(f"unable tp delete all user records due to {e} ")
        return HTTPException(500, f"Error delete record user due to {e}")


 


async def delete_user_records(token:Optional[str],id:Optional[int]):
 
    await delete_user(token=token,id=id)
