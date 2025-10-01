# Exercise 1 – FIX: Added access control check to prevent unauthorized profile access
def get_profile(user_id, current_user_id):
    if user_id != current_user_id:
        return {"error": "Unauthorized"}, 403
    user = db.query(User).filter_by(id=user_id).first()
    return user.to_dict()

# Exercise 2 – FIX: Enforced session-based access control using current_user
@app.route('/account/<user_id>')
def get_account(user_id):
    if current_user.id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    user = db.query(User).filter_by(id=user_id).first()
    return jsonify(user.to_dict())

# Exercise 3 – FIX: Replaced MD5 with bcrypt for secure password hashing
from passlib.hash import bcrypt
def hash_password_bcrypt(password):
    return bcrypt.hash(password)

# Exercise 4 – FIX: Replaced SHA1 with bcrypt and added salting
def hash_password_secure(password):
    return bcrypt.hash(password)

# Exercise 5 – FIX: Used parameterized query to prevent SQL injection
def get_user_by_username(username):
    query = "SELECT * FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    return cursor.fetchone()

# Exercise 6 – FIX: Sanitized input and validated schema to prevent NoSQL injection
def get_user_nosql_safe(username):
    if not isinstance(username, str) or not username.isalnum():
        return {"error": "Invalid input"}, 400
    query = { "username": username }
    return mongo_db.users.find_one(query)

# Exercise 7 – FIX: Added token-based verification for password reset
@app.route('/reset-password', methods=['POST'])
def reset_password():
    token = request.form['token']
    new_password = request.form['new_password']
    user = verify_token(token)
    if user:
        user.password = hash_password_secure(new_password)
        db.session.commit()
        return 'Password reset'
    return 'Invalid token', 403

# Exercise 8 – FIX: Added Subresource Integrity (SRI) to external script (simulated)
# <script src="https://cdn.example.com/lib.js"
#         integrity="sha384-abc123xyz456"
#         crossorigin="anonymous"></script>

# Exercise 9 – FIX: Validated URL and blocked internal IP ranges to prevent SSRF
import re
def fetch_url_safe():
    url = input("Enter URL: ")
    if re.match(r'^https?://(?!127\.|169\.254\.|localhost)', url):
        response = requests.get(url)
        print(response.text)
    else:
        print("Unsafe URL blocked")

# Exercise 10 – FIX: Used bcrypt for secure password comparison
def login(input_password, user):
    if bcrypt.verify(input_password, user.password):
        print("Login successful")
    else:
        print("Login failed")
