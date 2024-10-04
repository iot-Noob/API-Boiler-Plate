from App.LIbraryImport import *
from App.GetEnvDate import dap 
from App.LoggingInit import *
from App.SQL_Connector import session
from  App.CreateTable import Users
Route = APIRouter()

def admin_creation():
    try:
        admin=Users(name="admin",email="zjohndavid88@gmail.com",password=pwd_context.hash(dap) if dap else pwd_context.hash("Admin@123456"),profile_pic="",user_role="admin",disable=False)
        session.add(admin)
        session.commit()
     
        print("Admin user created successfully or already exists.")
        logging.info("Admin user created successfully or already exists.")

    except Exception as e:
        print(f"Fail to create admin due to {e}")
        logging.error(f"Fail to create admin due to {e}")
  
 


@Route.on_event("startup")
async def start():
 
    admin_creation()
  
    logging.info("API start sucess!!")
    print("ROUTE START SUCESS!!")
    pass


##AUTH USER

 


@Route.post(
    "/login", tags=["Auth User"], description="Login account with username and password"
)
async def login(username: str = Query(...), password: str = Query(...)):

    user_data =   authenticate_user(username=username, password=password)
 
    if user_data:

        access_token =  create_access_token(
            data={"sub": user_data[0], "user_id": user_data[2]}
        )
        return {"access_token": access_token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=401, detail="Invalid username or password")


@Route.post("/signup", tags=["Auth User"])
async def SignUp(data: User ):
    try:
       
        hashed_password = pwd_context.hash(data.password)
 
        existing_user = session.query(Users).filter(Users.name == data.name).one_or_none()

        if existing_user:
            raise HTTPException(status_code=400, detail="User already exists")    
        new_user = Users(
            name=data.name,
            email=data.email,
            password=hashed_password,
            profile_pic=data.profile_pic,
            user_role="user",  
            disable=data.disable
        )
        
        session.add(new_user)
        session.commit()
        
        return {"message": f"Successfully signed up account for {data.name}"}, 201   
        
    except Exception as e:
        session.rollback()   
        raise HTTPException(status_code=500, detail=f"Failed to sign up due to {str(e)}")

 

@Route.patch(path="/update_acount", tags=["account_settings and admin_roles"])
async def update_account(
    uud: UpdateUser, user_id: int | None = None, token: str = Depends(get_current_user)
):
    try:
        uid = token["id"]
        vtoken = authenticte_token(token=token)

        if not vtoken:
            raise HTTPException(
                status_code=404,
                detail="User not found, maybe your token is invalid or user does not exist",
            )

        current_user_role = get_user_role(token=token)
      
        if current_user_role == "admin":
       
            if not user_id:
                raise HTTPException(status_code=400, detail="User ID must be provided for admin updates")
            user = session.query(Users).filter(Users.id == user_id).one_or_none()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            
   
            if uud.name is not None:
                name_check = session.query(Users).filter(Users.name == uud.name).filter(Users.id != user_id).first()
                if name_check:
                    raise HTTPException(status_code=400, detail="Name is already in use by another account")

            if uud.email is not None:
                email_check = session.query(Users).filter(Users.email == uud.email).filter(Users.id != user_id).first()
                if email_check:
                    raise HTTPException(status_code=400, detail="Email is already in use by another account")
 
            if uud.name is not None:
                user.name = uud.name
            if uud.email is not None:
                user.email = uud.email
            if uud.password is not None:
                user.password = pwd_context.hash(uud.password)
            if uud.profile_pic is not None:
                user.profile_pic = uud.profile_pic
            if uud.user_role is not None:
                user.user_role = uud.user_role
            if uud.disable is not None:
                user.disable = uud.disable
            
            session.commit()
            return {"message": "Account updated successfully"}

        else:
 
            if user_id is not None and user_id != uid:
                raise HTTPException(
                    status_code=403, detail="You don't have admin rights to update another user's account"
                )
 
            if uud.disable is not None:
                raise HTTPException(status_code=403, detail="You cannot update the 'disable' field.")
            if uud.user_role is not None:
                raise HTTPException(status_code=403, detail="You cannot update the 'user_role' field.")
 
            user = session.query(Users).filter(Users.id == uid).one_or_none()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
 
            if uud.name is not None:
                name_check = session.query(Users).filter(Users.name == uud.name).filter(Users.id != uid).first()
                if name_check:
                    raise HTTPException(status_code=400, detail="Name is already in use by another account")

            if uud.email is not None:
                email_check = session.query(Users).filter(Users.email == uud.email).filter(Users.id != uid).first()
                if email_check:
                    raise HTTPException(status_code=400, detail="Email is already in use by another account")

          
            if uud.name is not None:
                user.name = uud.name
            if uud.email is not None:
                user.email = uud.email
            if uud.password is not None:
                user.password = pwd_context.hash(uud.password)
            if uud.profile_pic is not None:
                user.profile_pic = uud.profile_pic

            session.commit()
            return {"message": "Account updated successfully"}

    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating account: {e}")



@Route.delete("/delete_account", tags=["account_settings and admin_roles"])
async def delete_account(
    token: str = Depends(get_current_user),
    uid: int = None,
    password: str = Query(None, min_length=1, description="Only for users that are not admin.") 
):
    try:
        current_user_role = get_user_role(token=token)
        vtoken = authenticte_token(token=token)

        if not vtoken:
            raise HTTPException(
                status_code=404,
                detail="User not found. Your token may be invalid or the user does not exist.",
            )

        if current_user_role == "admin":
            # Admin deletion logic
            if not uid:
                raise HTTPException(status_code=400, detail="User ID cannot be null")
            
            user = session.query(Users).filter(Users.id == uid).one_or_none()
            if not user:
                raise HTTPException(status_code=404, detail="User does not exist")

            if uid == token["id"]:
                raise HTTPException(status_code=400, detail="Cannot delete yourself as an admin")

            # Delete the user
            session.delete(user)
            session.commit()

        else:
            # Non-admin deletion logic
            if uid:
                raise HTTPException(status_code=403, detail="You do not have admin rights to delete another user's account")

            user = session.query(Users).filter(Users.id == token["id"]).one_or_none()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            if user.disable:
                raise HTTPException(status_code=403, detail="Cannot delete account. Your account is disabled.")

            if not password:
                raise HTTPException(status_code=400, detail="Password is required")

            # Verify password
            if not   verify_password(password, user.password):
                raise HTTPException(status_code=400, detail="Incorrect password. Cannot delete account")

            # Delete the user's own account
            session.delete(user)
            session.commit()

        return {"message": "Account deleted successfully"}

    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"Error deleting account: {e}")

 

 