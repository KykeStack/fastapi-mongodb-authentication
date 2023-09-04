# fastapi-mongodb-auth

fastapi-mongodb-auth is a powerful authentication service built with FastAPI and MongoDB, designed to handle user authentication using email and password, as well as magic links for seamless login experiences.

This project is inspired in the Fastapi generator project:
- https://github.com/whythawk/full-stack-fastapi-postgresql.git

<img src="https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png" alt="FastAPI Logo" height="100">
<img src="https://webassets.mongodb.com/_com_assets/cms/mongodb_logo1-76twgcu2dm.png" alt="MongoDB Logo" height="100">
## Features

- User registration with email and password
- User login with email and password
- Magic link generation and login
- Token-based authentication using JWT (JSON Web Tokens)
- Secure password storage using bcrypt hashing
- MongoDB as the database for storing user information

## Prerequisites

Before you start, make sure you have the following prerequisites installed on your system:

- Python 3.7+
- MongoDB

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/KykeStack/fastapi-mongodb-authentication.git


2. Navigate to the project directory:

    ```bash
    cd fastapi-mongodb-auth

3. Activate the virtual environment::
    ```bash
    python3 -m venv venv


4. Create a virtual environment:
    ```bash
    source venv/bin/activate
    or source venv/Scripts/activate

5. Install the dependencies:
    ```bash
    pip install -r requirements.txt

6. Set up the MongoDB database:

    - Start the MongoDB service.
    - Create a new database for the application.
    - Prepare the mongourl
        - mongodb://[username:password@]host1[:port1][,...hostN[:portN]][/[defaultauthdb][?options]]

7. Configuration:
    - Rename the .env.example file to .env.
    - Open the .env file and provide the required configuration values, including the MongoDB connection URI and JWT secret key.

8. Run the application:
    ```bash
    cd app
    uvicorn main:app --reload

9. The app is now running. You can access the API documentation at http://localhost:8000.

# Usage
- Register a new user: Send a POST request to /api/v1/signup/ with the following JSON payload:
```json
    {
        "email": "example@example.com",
        "password": "password123",
        "username": "MyUser"
    }
```
    - This route has a series of optional fields, in case extra user information is required:
```json  
 {
   "fullName": {
     "name": "string",
     "secondName": "string",
     "surname": "string",
     "secondSurname": "string"
   },
   "birthdate": "string",
   "gender": "not_given",
   "country": "string",
   "phoneNumber": "string",
   "userExperience": true
 }
```  
- Login with email and password: Send a POST request to /login with the following JSON payload:
```curl
curl -X 'POST' \
  'http://127.0.0.1:8000/api/v1/signin/token' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=&username=user%40example.com&password=password123%2F&scope=&client_id=&client_secret='
```
- Generate and send a magic link: Send a POST request to /magic-link with the following JSON payload:
```curl
curl -X 'POST' \
  'http://127.0.0.1:8000/api/v1/login/magic/enrriqueorellana8%40gmail.com' \
  -H 'accept: application/json' \
  -d ''
```
- Verify a magic link and authenticate the user: Send a GET request to /magic-link/verify?token=<magic_link_token>. 
    - This is going to be assembled into the server host, the host will receive a claim and the user a bearer JWT Token, both are taken from the server host and sent to the API
The user will be authenticated and a JWT token will be returned. Example:
```curl
curl -X 'POST' \
  'http://127.0.0.1:8000/api/v1/login/claim' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer {token}\'
  -H 'Content-Type: application/json' \
  -d '{
  "claim": "string"
}'
```
- Access protected routes: Include the JWT token in the Authorization header of your requests:
    ```bash
    Authorization: Bearer <jwt_token>
    ```

- Logout the user session, this will deprecate any JWT token including the refresh token:

The user will be authenticated and a JWT token will be returned. Example:
```curl
    curl -X 'POST' \
    'http://127.0.0.1:8000/api/v1/logout/' \
    -H 'accept: application/json' \
```
- Access protected routes: Include the JWT token in the Authorization header of your requests:
    ```bash
    Authorization: Bearer <jwt_token>
    ```

- There is a long list of routes and possibilities, checkout the docs or Redocs of the API once you start it  🤩
    - admin
    - delete
    - login
    - proxy
    - services
    - signin
    - signup


# Emails
- EMAILS_ENABLED = true? on .env. Supply the necessary information of your SMTP provider

- The API sends:
    - New account created
    - Verification link of email when required
    - Web contact support
    - Magic Token is created for login
    - Password recovery
    - Delete User account

# fastapi-mongodb-auth Environment Variables

## Authentication and Tokens

- `ACCESS_TOKEN_EXPIRE_MINUTES`: The expiration time in minutes for an access token.
- `REFRESH_TOKEN_EXPIRE_MINUTES`: The expiration time in minutes for a refresh token.
- `JWT_ALGORITHM`: The algorithm used for JWT (JSON Web Token) encoding and decoding.
- `TOTP_ALGORITHM`: The algorithm used for Time-based One-Time Password (TOTP) generation.

## Database

- `DATABASE_NAME`: The name of the MongoDB database to connect to.
- `MONGODB_URL`: The URL for connecting to the MongoDB database.

## CORS (Cross-Origin Resource Sharing)

- `BACKEND_CORS_ORIGINS`: The list of allowed CORS origins for the backend API.

## Security and Cryptography

- `SECRET_KEY`: The secret key used for cryptographic operations.
- `TOTP_SECRET_KEY`: The secret key used for Time-based One-Time Password (TOTP) generation.

## Email Configuration

- `EMAILS_ENABLED`: A flag indicating whether email functionality is enabled.
- `EMAILS_TO_EMAIL`: The default email address to receive emails.
- `EMAILS_FROM_NAME`: The name to be used as the "From" name in outgoing emails.
- `EMAILS_FROM_EMAIL`: The email address to be used as the "From" address in outgoing emails.
- `SMTP_HOST`: The hostname of the SMTP server used for sending emails.
- `SMTP_PORT`: The port number of the SMTP server.
- `SMTP_TLS`: A flag indicating whether to use TLS for the SMTP connection.
- `SMTP_SSL`: A flag indicating whether to use SSL for the SMTP connection.
- `SMTP_USER`: The username for authenticating with the SMTP server.
- `SMTP_PASSWORD`: The password for authenticating with the SMTP server.

## Project and Server Configuration

- `PROJECT_NAME`: The name of your project.
- `EMAIL_TEMPLATES_DIR`: The directory path where the email templates are stored.
- `EMAIL_RESET_TOKEN_EXPIRE_HOURS`: The expiration time in hours for a password reset token.
- `SERVER_HOST`: The base URL of the website or server hosting the application.
- `SERVER_BOT`: The contact information for the server bot or administrator.
- `SERVER_NAME`: The name of the server or website.

Make sure to configure these environment variables according to your specific setup to properly run the `fastapi-mongodb-auth` API.



# Contributing
Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.
