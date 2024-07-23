# FastAPI Authentication Example
FastAPI Authentication Example
This project demonstrates how to use FastAPI with JWT for authentication, Argon2 for password hashing, and Two-Factor Authentication (2FA) for enhanced security. The application includes endpoints for user login, signup, account update, and account deletion.


## Prerequisites

- Python 3.7+
- FastAPI
- Uvicorn
- Argon2
- JWT
- SQLite (or any other database supported by your `RunQuery` function)
- `pyotp` for generating OTPs for 2FA
- `qrcode` for generating QR codes for 2FA
## Setup

1. **Install Dependencies**

   Ensure you have all necessary dependencies installed:

```bash
pip install fastapi uvicorn argon2-cffi python-jose python-dotenv pyotp qrcode
```
## 2. Create a .env file

```env
SECRET_KEY="your_secret_key_here"
ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES=790
databases_path="path_to_your_database.db" 
databases_name="tallha_database.db"
admin_paswd="123"
log_filepath="./logs/"
memory_costs=35555
pararellisms=1
hash_length=322
salt_length=16
time_cost=4
salt=""
pepper=""
comp_names="Iot Noob"
app_names="BoilerPlate FASTAPI "
```

- `SECRET_KEY:` Your secret key for encoding JWT tokens.
- `ALGORITHM:` The algorithm used for encoding JWT tokens.
- `ACCESS_TOKEN_EXPIRE_MINUTES:1 The expiration time for access     tokens in minutes.
- `databases_path:` Path to your database file.
- `databases_name:` Name to your database file like test.db for sqlite3. e.g. `talha.db`
- `ADMIN_PASSWORD:` Default password for the admin user.
- `LOG_FILEPATH:` Path for log file storage.
- “`memory_costs`, `pararellisms`, `hash_length`, `salt_length`: Parameters for Argon2 config”
- `SALT:` additional to secure password
- `PEPPER` additional to secure password
- `comp_names` name of company for 2FA Authenticator
- `app_names` name of application for 2fa
## Database Setup
Ensure your database schema is set up correctly. This application assumes you have a users table with the following columns:

- **`name`**
- **`email`**
- **`password`**
- **`profile_pic`**
- **`user_role`**
- **`disabled`**

## Endpoints
### Login
- **URL:** `/login`
**Method:** `POST`
**Description:** `Login with username, password, and 2FA code (if required).`
- ### Request Body:
```json
{
  "username": "string",
  "password": "string",
  "two_factor_code": "string"  // Optional, required if 2FA is enabled for the account
}

```

**Query Parameters:**
**username:** `The username of the account.`
**password:** `The password of the account.`
### **Responses:**
- `200 OK:` Returns an access token if login is successful.
- ***`401 Unauthorized:`*** Invalid username, password, or 2FA code.
- ***`403 Forbidden:`*** 2FA code required but not provided.
### ***Login with 2FA:***

1. When logging in, if 2FA is enabled for the account, the two_factor_code parameter is required.
2. The provided 2FA code will be verified against the user's stored 2FA key.
3. If the 2FA code is valid, an access token will be issued.
### **Signup**
- **URL:** `/signup`
- **Method:** `POST`
- **Description:** Create a new user account.
```json
{
  "name": "string",
  "email": "string",
  "password": "string",
  "profile_pic": "string",
  "disable": boolean
}

```
##  Responses:
- **200 OK:** Account created successfully.
- **500 Internal Server Error:** Failed to sign up due to server error.

## Update Account
- **URL:** /update_acount
- **Method:** PATCH
- **Description:** Update user account details.
- **Request Body**
```json
{
  "name": "string",
  "email": "string",
  "password": "string",
  "profile_pic": "string",
  "user_role": "string",
  "disable": boolean
}

```


- **Query Parameters:**
**`user_id:`** ID of the user to update (admin only).
- **`Responses:`**
- **`200 OK:`** Account updated successfully.
- **`400 Bad Request:`** No update fields provided.
- **`404 Not Found:`** User not found.
- **`500 Internal Server Error:`** Error updating account.
### Delete Account
- **URL: /delete_account**
- **Method: DELETE**
- **`Description: Delete user account.**
- **`Query Parameters:**
- **`uid: ID of the user to delete (admin only).**
- **`password: Password of the account (for non-admin - users).`**
- ### Responses:
- ***`200 OK:`*** Account deleted successfully.
- ***`400 Bad Request:`*** Invalid request parameters.
- ***`401 Unauthorized:`*** Invalid token or password.
- ***`404 Not Found:`*** User not found.
- ***`500 Internal Server Error:`*** Error deleting account.

### Running the Application

To run the FastAPI application, use Uvicorn:

```bash
uvicorn main:app --reload
```
Replace `main` with the name of your Python file if it's different.

### Logging
Logs are stored in the directory specified by **`LOG_FILEPATH`** in the **`.env`** file.
### Security
- Passwords are hashed using Argon2.
- JWT tokens are used for authentication and have an expiration time.
### Notes
- Ensure to replace placeholder values in the .env file with your actual configuration.
- Update database paths and configurations according to your environment.
 
### Project Information
This is a private project named iotNoob by Talha.