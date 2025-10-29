from flask import Flask, request, jsonify, make_response, render_template
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from bson.objectid import ObjectId
from flask_cors import CORS
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Timezones
ist_timezone = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
utc_timezone = datetime.timezone.utc

app = Flask(__name__, template_folder='templates')

# --- CONFIG ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-strong-default-secret-key-for-dev')
app.config['MONGO_URI'] = os.environ.get('MONGO_URI')

if not app.config['MONGO_URI']:
    print("FATAL ERROR: MONGO_URI environment variable is not set.")
    exit()

mongo = PyMongo(app)
CORS(app)

try:
    users_collection = mongo.db.users
    sessions_collection = mongo.db.sessions
    messages_collection = mongo.db.messages  # <-- Added for storing messages

    users_collection.create_index('username', unique=True)
    print("Connected to MongoDB and collections are ready.")

    admin_username = 'admin'
    admin_password = os.environ.get("ADMIN_PASSWORD")

    if admin_password:
        hashed_password = generate_password_hash(admin_password)
        admin_user = users_collection.find_one({'username': admin_username})

        if not admin_user:
            print(f"Admin user '{admin_username}' not found. Creating...")
            users_collection.insert_one({
                'username': admin_username,
                'password': hashed_password,
                'role': 'admin'
            })
            print(f"Admin user '{admin_username}' created successfully.")
        else:
            print(f"Admin user '{admin_username}' already exists. Syncing password...")
            users_collection.update_one(
                {'_id': admin_user['_id']},
                {'$set': {'password': hashed_password}}
            )
            print(f"Admin user '{admin_username}' password synced.")
    else:
        print("ADMIN_PASSWORD not set. Skipping admin creation.")

except Exception as e:
    print(f"Error connecting to MongoDB: {e}")


@app.route('/')
def serve_index():
    return render_template('index.html')

# ---------------- AUTH HELPERS ----------------
def admin_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'error': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = users_collection.find_one({'_id': ObjectId(data['user_id'])})
            if not current_user or current_user.get('role') != 'admin':
                return jsonify({'error': 'Admin role required!'}), 403
        except Exception as e:
            return jsonify({'error': 'Token is invalid!', 'details': str(e)}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# ---------------- REGISTER ----------------
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    hashed_password = generate_password_hash(password)
    try:
        users_collection.insert_one({
            'username': username,
            'password': hashed_password,
            'role': 'user'
        })
        return jsonify({'message': 'User registered successfully!'}), 201
    except Exception as e:
        return jsonify({'error': 'Username already exists', 'details': str(e)}), 400

# ---------------- LOGIN ----------------
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Missing credentials'}), 400

    user = users_collection.find_one({'username': username})
    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401

    pwhash = user['password']
    if isinstance(pwhash, bytes):
        pwhash = pwhash.decode('utf-8')

    if not check_password_hash(pwhash, password):
        return jsonify({'error': 'Invalid username or password'}), 401

    session_insert = sessions_collection.insert_one({
        'user_id': user['_id'],
        'login_time': datetime.datetime.now(ist_timezone),
        'logout_time': None
    })
    session_id = str(session_insert.inserted_id)

    token = jwt.encode({
        'user_id': str(user['_id']),
        'role': user.get('role'),
        'exp': datetime.datetime.now(ist_timezone) + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({
        'message': 'Login successful!',
        'token': token,
        'role': user.get('role'),
        'session_id': session_id
    }), 200

# ---------------- LOGOUT ----------------
@app.route('/logout', methods=['POST'])
def logout():
    data = request.get_json()
    session_id = data.get('session_id')
    if not session_id:
        return jsonify({'error': 'Session ID missing'}), 400

    result = sessions_collection.update_one(
        {'_id': ObjectId(session_id), 'logout_time': None},
        {'$set': {'logout_time': datetime.datetime.now(ist_timezone)}}
    )
    if result.matched_count == 0:
        return jsonify({'error': 'Session not found or already logged out'}), 404
    return jsonify({'message': 'Logout successful!'}), 200

# ---------------- FORGOT PASSWORD ----------------
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    username = data.get('username')
    new_password = data.get('new_password')
    if not username or not new_password:
        return jsonify({'error': 'Username and new password are required'}), 400

    user = users_collection.find_one({'username': username})
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.get('username') == 'admin':
        return jsonify({'error': 'Cannot reset admin password here'}), 403

    hashed_password = generate_password_hash(new_password)
    users_collection.update_one({'_id': user['_id']}, {'$set': {'password': hashed_password}})
    return jsonify({'message': 'Password reset successful!'}), 200

# ---------------- ADMIN: USERS + 20 message cap ----------------
@app.route('/admin/users', methods=['GET'])
@admin_token_required
def get_all_users(current_user):
    try:
        pipeline = [
            {'$lookup': {
                'from': 'sessions',
                'localField': '_id',
                'foreignField': 'user_id',
                'as': 'sessions'
            }},
            {'$project': {'password': 0, 'sessions.user_id': 0}}
        ]
        users_with_sessions = list(users_collection.aggregate(pipeline))

        time_format = '%d-%m-%Y %I:%M %p IST'

        for user in users_with_sessions:
            user['_id'] = str(user['_id'])
            for session in user.get('sessions', []):
                session['_id'] = str(session['_id'])
                for key in ['login_time', 'logout_time']:
                    t = session.get(key)
                    if t:
                        t = t.replace(tzinfo=utc_timezone).astimezone(ist_timezone)
                        session[key] = t.strftime(time_format)
                    else:
                        session[key] = '-'

        # Keep only the latest 20 messages (sorted by time)
        recent_sessions = []
        for user in users_with_sessions:
            user['sessions'] = sorted(user.get('sessions', []), key=lambda x: x.get('login_time', '-'), reverse=True)[:100]

        return jsonify(users_with_sessions), 200
    except Exception as e:
        return jsonify({'error': 'Could not fetch users', 'details': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)

