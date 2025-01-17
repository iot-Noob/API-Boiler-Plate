from App.LIbraryImport import *
from App.GetEnvDate import dap 
from App.LoggingInit import *
from App.DeleteTables import *

Route = APIRouter()


async def admin_creation():
    try:

        query = """ 
            INSERT INTO users (name, email, password, profile_pic, user_role, disabled)
            SELECT ?, ?, ?, ?, ?, ?
            WHERE NOT EXISTS (
                SELECT 1 FROM users WHERE name = ? OR email = ?
            );
        """
        values = (
            "admin",
            "talhakhalid2018@gmail.com",
            pwd_context.hash(dap),
            "",
            "admin",
            0,
            "admin",
            "talhakhalid2018@gmail.com",
        )

        await RunQuery(q=query, val=values)
        guu = await RunQuery(
            q=""" SELECT name,id FROM users WHERE name=? """, val=("admin",)
        )
       
    
   
        print("Admin user created successfully or already exists.")
        logging.info("Admin user created successfully or already exists.")

    except Exception as e:
        print(f"Fail to create admin due to {e}")
        logging.error(f"Fail to create admin due to {e}")
  
 


@Route.on_event("startup")
async def start():
    #await delete_all()
    await admin_creation()
  
    logging.info("API start sucess!!")
    print("ROUTE START SUCESS!!")
    pass


##AUTH USER

 


@Route.post(
    "/login", tags=["Auth User"], description="Login account with username and password"
)
async def login(username: str = Query(...), password: str = Query(...)):
    user_data = await authenticate_user(username=username, password=password)

    if user_data:

        access_token = await create_access_token(
            data={"sub": user_data[0], "user_id": user_data[2]}
        )
        return {"access_token": access_token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=401, detail="Invalid username or password")


@Route.post("/signup", tags=["Auth User"])
async def SignUp(data: User):
    try:
        # Hash the password before storing it
        hashed_password = pwd_context.hash(data.password)

        # Perform the insert operation
        idata = await RunQuery(
            q=""" 
                INSERT INTO users (
                    name,
                    email,
                    password,
                    profile_pic,
                    disabled,
                    user_role
                )               
                VALUES (?, ?, ?, ?, ?,?); """,
            val=(
                data.name,
                data.email,
                hashed_password,
                data.profile_pic,
                data.disable,
                "user",
            ),
            fetch_om="ONE",
            exec_om=False,
        )
     
  
        return {"message": f"Successfully signed up account for {data.name}"}
    except Exception as e:

        raise HTTPException(status_code=500, detail=f"Failed to sign up due to {e}")


@Route.patch(path="/update_acount", tags=["account_settings and admin_roles"])
async def update_account(
    uud: UpdateUser, user_id: int | None = None, token: str = Depends(get_current_user)
):
    try:
        update_fields = []
        update_values = []
        uid = token["id"]
        vtoken = await authenticte_token(token=token)
        if not vtoken:
            raise HTTPException(
                404,
                "User not found cant update maybe your toen in invalid or user not exist",
            )
        current_userole = await get_user_role(token=token)

        if current_userole[0] == "admin":
            gcu = await RunQuery(
                q=""" SELECT name,id FROM users WHERE id=? """, val=(user_id,)
            )
            if not gcu:
                return HTTPException(404, "User not found, Invalid user cant update")

            if uud.name is not None:
                update_fields.append("name = ?")
                update_values.append(uud.name)
            if uud.email is not None:
                update_fields.append("email = ?")
                update_values.append(uud.email)
            if uud.password is not None:
                update_fields.append("password = ?")
                update_values.append(pwd_context.hash(uud.password))
            if uud.profile_pic is not None:
                update_fields.append("profile_pic = ?")
                update_values.append(uud.profile_pic)
            if uud.user_role is not None:
                update_fields.append("user_role = ?")
                update_values.append(uud.user_role)
            if uud.disable is not None:
                update_fields.append("disabled = ?")
                update_values.append(uud.disable)
            if not update_fields:
                raise HTTPException(
                    status_code=400, detail="No update fields provided."
                )
            update_values.append(user_id)
            update_query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"

        else:
            if user_id:
                return HTTPException(
                    500, "You dnt have admin right to access or update acount"
                )
            if uud.name is not None:
                update_fields.append("name = ?")
                update_values.append(uud.name)
            if uud.email is not None:
                update_fields.append("email = ?")
                update_values.append(uud.email)
            if uud.password is not None:
                update_fields.append("password = ?")
                update_values.append(pwd_context.hash(uud.password))
            if uud.profile_pic is not None:
                update_fields.append("profile_pic = ?")
                update_values.append(uud.profile_pic)
            if uud.user_role is not None:
                update_fields.append("user_role = ?")
                update_values.append(uud.user_role)
            if uud.disable is not None:
                update_fields.append("disabled = ?")
                update_values.append(uud.disable)
            if not update_fields:
                raise HTTPException(
                    status_code=400, detail="No update fields provided."
                )
            update_values.append(uid)
            update_query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
        await RunQuery(q=update_query, val=update_values)
        return {"message": "Account updated successfully"}
    except Exception as e:
        raise HTTPException(500, f"Error update account due to {e}")


@Route.delete("/delete_account", tags=["account_settings and admin_roles"])
async def delete_account(
    token: str = Depends(get_current_user),
    uid: int = None,
    password: str = Query(None, min_length=1,description="Only for users that are not admin."),
):
    
    current_userole = await get_user_role(token=token)
    vtoken = await authenticte_token(token=token)
 
    cuhp = await RunQuery(q="SELECT password,disabled FROM users WHERE id=?", val=(token["id"],))
 
    if not vtoken:
        raise HTTPException(
            404,
            "User not found cant update maybe your toen in invalid or user not exist",
        )
  
    if current_userole[0] == "admin":
        
        cue=await RunQuery(q="SELECT id FROM users WHERE id=?",val=(uid,))
        if not cue:
            return HTTPException(404,"Canot delete user user dont exist")
        if not uid:
            return HTTPException(400,"User id canot be null")
        if uid == token["id"]:
            return HTTPException(400, "Canot delete admin permission denied!!")
        dr=await delete_user_records(id=uid, token=None)

    else:
        if uid:
            return HTTPException(402, "Canot delete account dont have admin access")
        if not cuhp:
            return HTTPException(404,"User dont exist")
        if cuhp[1]==True:
            return HTTPException(500,"Canot delete account your account is disabled")
        if not password:
            return HTTPException(404, "Password is empty")
        if not await verify_password(password, cuhp[0]):
            return HTTPException(400, "Password didnt match cantnot delete account!!")
        else:
            await delete_user_records(token=token, id=None)
    return HTTPException(200, f"Account delete sucess!!  ")

 

 