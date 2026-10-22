# py.tech Login (Flask)

- Password hashing: Argon2id (argon2-cffi)
- 3 wrong attempts => that DEVICE (cookie device_id) is permanently blocked
- After login: "Welcome to py.tech"

## Run locally
    pip install -r requirements.txt
    python app.py
Open http://127.0.0.1:5000

## Deploy (Render.com)
1. Push this folder to GitHub.
2. Render -> New Web Service -> connect the repo.
3. Build command:  pip install -r requirements.txt
4. Start command:  gunicorn app:app
5. Environment variables: SECRET_KEY = <long random string>, HTTPS = 1

Note: free hosting may reset the SQLite file on redeploy; use a persistent disk or PostgreSQL for real use.
