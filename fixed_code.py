# Common imports
from flask import Flask, request, jsonify
from passlib.hash import bcrypt
import re
import requests

app = Flask(__name__)

# Exercise 1 – Access control for profile access
def get_profile(user_id, current_user_id):
    if user_id != current_user_id:
        return {"error": "Unauthorized"}, 403
    user = db.query(User).filter_by(id=user_id).first()
    return user.to_dict() if user else {"error": "User not found"}, 404

# Exercise 2 – Session-based access control
@app.route('/account/<int:user_id>')
def get_account(user_id):
    if current_user.id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    user = db.query(User).filter_by(id=user_id).first()
    return jsonify(user.to_dict()) if user else jsonify({'error': 'User not found'}), 404

# Exercise 3 & 4 – Secure password hashing with bcrypt
def hash_password_bcrypt(password):
    return bcrypt.hash(password)

def hash_password_secure(password):
    return bcrypt.hash(password)

# Exercise 5 – SQL injection prevention
def get_user_by_username(username):
    query = "SELECT * FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    return cursor.fetchone()

# Exercise 6 – NoSQL injection prevention
def get_user_nosql_safe(username):
    if not isinstance(username, str) or not username.isalnum():
        return {"error": "Invalid input"}, 400
    query = {"username": username}
    user = mongo_db.users.find_one(query)
    return user if user else {"error": "User not found"}, 404

# Exercise 7 – Token-based password reset
@app.route('/reset-password', methods=['POST'])
def reset_password():
    token = request.form.get('token')
    new_password = request.form.get('new_password')
    user = verify_token(token)
    if user:
        user.password = hash_password_secure(new_password)
        db.session.commit()
        return jsonify({'message': 'Password reset successful'})
    return jsonify({'error': 'Invalid token'}), 403

# Exercise 8 – Subresource Integrity (SRI) example (HTML snippet)
# <script src="https://cdn.example.com/lib.js"
#         integrity="sha384-abc123xyz456"
#         crossorigin="anonymous"></script>

# Exercise 9 – SSRF protection
def fetch_url_safe():
    url = input("Enter URL: ").strip()
    if re.match(r'^https?://(?!127\.|169\.254\.|localhost)', url):
        try:
            response = requests.get(url, timeout=5)
            print(response.text)
        except requests.RequestException as e:
            print(f"Request failed: {e}")
    else:
        print("Unsafe URL blocked")

# Exercise 10 – Secure password comparison
def login(input_password, user):
    if bcrypt.verify(input_password, user.password):
        print("Login successful")
    else:
        print("Login failed")


