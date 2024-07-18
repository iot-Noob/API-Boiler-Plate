from App.RunQuery import RunQuery


async def create_table_user():
    try:
        await RunQuery(
            q="""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(200) NOT NULL UNIQUE,
                    email VARCHAR(200) NOT NULL UNIQUE,
                    password VARCHAR(200) NOT NULL,
                    profile_pic VARCHAR(255),
                    user_role VARCHAR(50) NOT NULL,
                    disabled INTEGER DEFAULT 0
                );
                        """,
            val=(),
            fetch_om="ONE",
            exec_om=False,
        )
    except Exception as e:
        print(f"Error creating user table due to {e}")

 
 

 
