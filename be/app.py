from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_cors import CORS

app = Flask(__name__)

# ✅ Security & Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this!
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

CORS(app)  # Allow frontend requests if needed

# ✅ User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ✅ Route to Register Users
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required!"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already exists!"}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')  # ✅ Use bcrypt
    new_user = User(username=username, password=hashed_password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully!"}), 201

# ✅ Route to Login Users
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required!"}), 400

    user = User.query.filter_by(username=username).first()
    
    if user:
        print(f"Stored Hash: {user.password}")  # Debugging Step
        print(f"Entered Password: {password}")  

    if user and bcrypt.check_password_hash(user.password, password):
        login_user(user)
        return jsonify({'message': 'Login successful!', 'user': user.username}), 200

    return jsonify({'message': 'Invalid username or password'}), 401


# ✅ Route to Logout Users
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully!'}), 200

# ✅ Route to Check if User is Logged In
@app.route('/check-login', methods=['GET'])
def check_login():
    return jsonify({
        'logged_in': current_user.is_authenticated,
        'user': current_user.username if current_user.is_authenticated else None
    }), 200

# ✅ Create database tables
with app.app_context():
    db.create_all()
    print("✅ Database tables created successfully!")

# ✅ Run Flask App
if __name__ == '__main__':
    app.run(debug=True)
