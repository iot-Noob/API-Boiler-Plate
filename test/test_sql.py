from App.core.Connector import DatabaseConnector,get_asyncpg_connection
import asyncio
async def cot():
    conn=get_asyncpg_connection()
    conn.execute("SELECT * FROM users")
    pass

if __name__=="__main__":
    asyncio.run(cot())