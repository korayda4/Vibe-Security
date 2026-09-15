"""Python test fixture — SQL injection, weak hashing, mass assignment."""
import hashlib
from flask import Flask, request

app = Flask(__name__)

# CI-002: hardcoded secret
AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"

@app.route("/api/user/<user_id>")
def get_user(user_id):
    # BE-001: IDOR
    user = db.users.find_one(id=user_id)
    return {"user": user}

@app.route("/api/login", methods=["POST"])
def login():
    email = request.json["email"]
    password = request.json["password"]
    # BE-004: SQL injection via f-string
    user = db.execute(f"SELECT * FROM users WHERE email = '{email}' AND password = '{password}'")
    if user:
        # BE-002: weak hashing
        token = hashlib.md5(password.encode()).hexdigest()
        return {"token": token}
    return {"error": "invalid"}
