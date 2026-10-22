# py.tech Login (Flask)

- Fixed login from environment variables (ADMIN_USERNAME / ADMIN_PASSWORD), no register page
- Password check uses Argon2id (argon2-cffi)
- 3 wrong attempts => that DEVICE (cookie device_id) is permanently blocked
- After login: "Welcome to py.tech"

## Deploy (Render.com)
Build command:  pip install -r requirements.txt
Start command:  gunicorn app:app

Environment variables:
- ADMIN_USERNAME = your username
- ADMIN_PASSWORD = your strong password
- SECRET_KEY     = long random string (python -c "import secrets; print(secrets.token_hex(32))")
- HTTPS          = 1

Note: free hosting may reset the SQLite file on redeploy, so device blocks can reset.
