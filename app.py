from flask import Flask, request, jsonify, make_response, send_from_directory, render_template
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from bson.objectid import ObjectId
from flask_cors import CORS
import os
from dotenv import load_dotenv # <-- IMPORT THIS

load_dotenv() # <-- ADD THIS LINE to load the .env file

# Define IST Timezone
ist_timezone = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
utc_timezone = datetime.timezone.utc # <-- Added UTC for clarity

app = Flask(__name__, template_folder='templates') # Tell Flask where to find templates

# --- CONFIGURATION ---
# This will now read the MONGO_URI from your .env file
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-strong-default-secret-key-for-dev')
app.config['MONGO_URI'] = os.environ.get('MONGO_URI') # <-- REMOVED THE LOCALHOST DEFAULT

if not app.config['MONGO_URI']:
    print("FATAL ERROR: MONGO_URI environment variable is not set.")
    # Exit or raise error because MONGO_URI is required
    exit()

mongo = PyMongo(app)
CORS(app) # Enable Cross-Origin Resource Sharing for all routes

# --- Database Collections ---
# These lines create 'users' and 'sessions' collections if they don't exist
# We use 'db' from the mongo object provided by Flask-PyMongo
try:
    users_collection = mongo.db.users
    sessions_collection = mongo.db.sessions
    # Create a unique index on 'username' to prevent duplicates
    users_collection.create_index('username', unique=True)
    print("Connected to MongoDB and collections are ready.")


    # --- !! START OF SECURE ADMIN CREATION/UPDATE !! ---
    # Load BOTH admin username and password from environment variables
    admin_username = os.environ.get("ADMIN_USERNAME")
    admin_password = os.environ.get("ADMIN_PASSWORD")

    # Only try to create/update an admin if BOTH are provided
    if admin_username and admin_password:
        hashed_password = generate_password_hash(admin_password)
        admin_user = users_collection.find_one({'username': admin_username})

        if not admin_user:
            # If admin doesn't exist, create it
            print(f"Admin user '{admin_username}' not found. Creating...")
            users_collection.insert_one({
                'username': admin_username,
                'password': hashed_password,
                'role': 'admin'
            })
            print(f"Admin user '{admin_username}' created successfully.")
        else:
            # If admin exists, update its password to match the .env file
            print(f"Admin user '{admin_username}' already exists. Syncing password...")
            users_collection.update_one(
                {'_id': admin_user['_id']},
                {'$set': {'password': hashed_password}}
            )
            print(f"Admin user '{admin_username}' password has been synced with environment variable.")
    else:
        # This will show in your logs if you forget to set the variable
        print("ADMIN_USERNAME or ADMIN_PASSWORD environment variable not set. Skipping admin creation/update.")
    # --- !! END OF SECURE ADMIN CREATION/UPDATE !! ---

except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    # Handle connection error appropriately in a real app


# --- Serve HTML App ---
@app.route('/')
def serve_index():
    # This route serves your main HTML file from the 'templates' folder
    return render_template('index.html')

# --- Admin Token Decorator ---
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
        except jwt.ExpiredSignatureError:
             return jsonify({'error': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
             return jsonify({'error': 'Token is invalid!'}), 401
        except Exception as e:
            return jsonify({'error': 'Token validation error', 'details': str(e)}), 401

        return f(current_user, *args, **kwargs)
    return decorated

# --- REGISTRATION ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    hashed_password = generate_password_hash(password)

    # All new registrations are 'user'
    role = 'user'

    try:
        users_collection.insert_one({
            'username': username,
            'password': hashed_password,
            'role': role
        })
        return jsonify({'message': 'User registered successfully!'}), 201
    except Exception as e:
        # This will catch duplicate usernames
        if 'duplicate key error' in str(e).lower():
             return jsonify({'error': 'Username already exists'}), 400
        return jsonify({'error': 'Database error during registration', 'details': str(e)}), 500

# --- LOGIN ---
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = users_collection.find_one({'username': username})

    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401

    # --- FIX for TypeError ---
    pwhash = user.get('password', '') # Use .get() for safety
    if isinstance(pwhash, bytes):
        pwhash = pwhash.decode('utf-8')
    # --- End of FIX ---

    # --- !! START OF SIMPLIFIED SECURE LOGIN !! ---
    if check_password_hash(pwhash, password):
        pass # Continue
    else:
        return jsonify({'error': 'Invalid username or password'}), 401
    # --- !! END OF SIMPLIFIED SECURE LOGIN !! ---


    # Create a new session
    try:
        session_insert = sessions_collection.insert_one({
            'user_id': user['_id'],
            'login_time': datetime.datetime.now(utc_timezone), # Store time in UTC
            'logout_time': None
        })
        session_id = str(session_insert.inserted_id)

        # Create JWT token
        token = jwt.encode({
            'user_id': str(user['_id']),
            'role': user.get('role'),
            'exp': datetime.datetime.now(utc_timezone) + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({
            'message': 'Login successful!',
            'token': token,
            'role': user.get('role'),
            'session_id': session_id # Send session_id to client
        }), 200

    except Exception as e:
        return jsonify({'error': 'Could not create session', 'details': str(e)}), 500

# --- LOGOUT ---
@app.route('/logout', methods=['POST'])
def logout():
    data = request.get_json()
    session_id = data.get('session_id')

    if not session_id:
        return jsonify({'error': 'Session ID is missing'}), 400

    try:
        # Find the session and update its logout time
        result = sessions_collection.update_one(
            {'_id': ObjectId(session_id), 'logout_time': None},
            {'$set': {'logout_time': datetime.datetime.now(utc_timezone)}} # Store time in UTC
        )

        if result.matched_count == 0:
            # It's okay if the session wasn't found or was already logged out, just return success
            print(f"Logout attempt for session {session_id}: Not found or already logged out.")
        else:
             print(f"Logout successful for session {session_id}.")

        # Always return success on logout attempt to avoid info leakage
        return jsonify({'message': 'Logout successful!'}), 200
    except Exception as e:
         # Log the error but still return success to the client
        print(f"Error during logout for session {session_id}: {e}")
        return jsonify({'message': 'Logout processed.'}), 200 # Return generic success


# --- FORGOT PASSWORD ---
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    username = data.get('username')
    new_password = data.get('new_password')

    # Get the admin username from env
    admin_username = os.environ.get("ADMIN_USERNAME")

    if not username or not new_password:
        return jsonify({'error': 'Username and new password are required'}), 400

    # --- !! START OF NEW ADMIN-PROTECT FIX !! ---
    if username == admin_username:
        return jsonify({'error': "Cannot reset the admin's password from this page."}), 403
    # --- !! END OF NEW ADMIN-PROTECT FIX !! ---

    user = users_collection.find_one({'username': username})
    if not user:
        return jsonify({'error': 'User not found'}), 404


    hashed_password = generate_password_hash(new_password)

    try:
        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {'password': hashed_password}}
        )
        return jsonify({'message': 'Password reset successful!'}), 200
    except Exception as e:
        return jsonify({'error': 'Could not reset password', 'details': str(e)}), 500


# --- ADMIN: Get All Users and their Sessions ---
@app.route('/admin/users', methods=['GET'])
@admin_token_required
def get_all_users(current_user):
    print("\n--- ADMIN: /admin/users route hit ---")
    try:
        print("--- Running aggregation pipeline ---")
        pipeline = [
            { '$match': {} }, # Match all users initially
            {
                '$lookup': {
                    'from': 'sessions',
                    'localField': '_id',
                    'foreignField': 'user_id',
                    'as': 'sessions'
                }
            },
             # Sort sessions within each user - newest first (optional but nice)
            {
                '$unwind': {
                    'path': '$sessions',
                    'preserveNullAndEmptyArrays': True # Keep users with no sessions
                }
            },
            { '$sort': { 'sessions.login_time': -1 } },
            # Group back by user to reconstruct the sessions array
            {
                '$group': {
                    '_id': '$_id',
                    'username': { '$first': '$username' },
                    'role': { '$first': '$role' },
                    # Collect sessions back into an array, handle null sessions
                     'sessions': {
                         '$push': {
                             '$cond': [ { '$ne': ["$sessions", None] }, "$sessions", "$$REMOVE" ]
                         }
                     }
                }
            },
             # Sort users alphabetically by username
            { '$sort': { 'username': 1 } },
            {
                '$project': {
                    'password': 0, # Exclude password
                    'sessions.user_id': 0 # Exclude user_id from nested sessions
                }
            }
        ]
        users_with_sessions = list(users_collection.aggregate(pipeline))
        print(f"--- Aggregation returned {len(users_with_sessions)} users ---")

        # --- IST TIME CONVERSION ---
        time_format = '%d/%m/%y, %I:%M %p IST' # DD/MM/YY, HH:MM AM/PM IST

        for user in users_with_sessions:
            user['_id'] = str(user['_id']) # Convert user ID
            # Ensure sessions is always a list, even if aggregation returns null/missing
            sessions_list = user.get('sessions', [])
            if not isinstance(sessions_list, list): sessions_list = [] # Safeguard
            
            processed_sessions = []
            for session in sessions_list:
                 # Check if session is a valid dictionary before processing
                if not isinstance(session, dict): continue

                session['_id'] = str(session.get('_id')) # Convert session ID safely

                # Convert Login Time
                try:
                    login_time_obj = session.get('login_time')
                    if login_time_obj and isinstance(login_time_obj, datetime.datetime):
                        aware_utc_time = login_time_obj.replace(tzinfo=utc_timezone)
                        ist_login_time = aware_utc_time.astimezone(ist_timezone)
                        session['login_time'] = ist_login_time.strftime(time_format)
                    else:
                         session['login_time'] = '-' # Handle missing or invalid type
                except Exception as e:
                    print(f"Error converting login_time for session {session.get('_id')}: {e}")
                    session['login_time'] = '-'

                # Convert Logout Time
                try:
                    logout_time_obj = session.get('logout_time')
                    if logout_time_obj and isinstance(logout_time_obj, datetime.datetime):
                        aware_utc_time = logout_time_obj.replace(tzinfo=utc_timezone)
                        ist_logout_time = aware_utc_time.astimezone(ist_timezone)
                        session['logout_time'] = ist_logout_time.strftime(time_format)
                    else:
                        session['logout_time'] = '-' # Handle missing or invalid type
                except Exception as e:
                    print(f"Error converting logout_time for session {session.get('_id')}: {e}")
                    session['logout_time'] = '-'
                
                processed_sessions.append(session) # Add processed session
            
            user['sessions'] = processed_sessions # Replace original sessions with processed ones


        print(f"--- Returning data for {len(users_with_sessions)} users to frontend ---")
        return jsonify(users_with_sessions), 200
    except Exception as e:
        print(f"--- ERROR in /admin/users: {e} ---")
        return jsonify({'error': 'Could not fetch users', 'details': str(e)}), 500

# --- ADMIN: Delete User ---
@app.route('/admin/user/<string:user_id>', methods=['DELETE'])
@admin_token_required
def delete_user(current_user, user_id):
    admin_username = os.environ.get("ADMIN_USERNAME")
    try:
        user_to_delete = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user_to_delete: return jsonify({'error': 'User not found'}), 404
        if user_to_delete.get('username') == admin_username:
            return jsonify({'error': 'Cannot delete the admin user'}), 403

        delete_user_result = users_collection.delete_one({'_id': ObjectId(user_id)})
        if delete_user_result.deleted_count == 0: return jsonify({'error': 'User not found'}), 404

        sessions_collection.delete_many({'user_id': ObjectId(user_id)})
        return jsonify({'message': 'User deleted. All associated sessions deleted.'}), 200
    except Exception as e:
        return jsonify({'error': 'Invalid User ID or database error', 'details': str(e)}), 500

# --- ADMIN: Delete Session ---
@app.route('/admin/session/<string:session_id>', methods=['DELETE'])
@admin_token_required
def delete_session(current_user, session_id):
    try:
        result = sessions_collection.delete_one({'_id': ObjectId(session_id)})
        if result.deleted_count == 0: return jsonify({'error': 'Session not found'}), 404
        return jsonify({'message': 'Session deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': 'Invalid Session ID or database error', 'details': str(e)}), 500

# --- ADMIN: Reset User Password ---
@app.route('/admin/user/<string:user_id>/reset-password', methods=['POST'])
@admin_token_required
def admin_reset_password(current_user, user_id):
    admin_username = os.environ.get("ADMIN_USERNAME")
    try:
        user_to_reset = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user_to_reset: return jsonify({'error': 'User not found'}), 404
        if user_to_reset.get('username') == admin_username:
            return jsonify({'error': "Cannot reset the admin user's password"}), 403
    except Exception as e:
         return jsonify({'error': 'Invalid User ID', 'details': str(e)}), 400

    data = request.get_json()
    new_password = data.get('new_password')
    if not new_password: return jsonify({'error': 'New password is required'}), 400

    hashed_password = generate_password_hash(new_password)
    try:
        result = users_collection.update_one( {'_id': ObjectId(user_id)}, {'$set': {'password': hashed_password}} )
        if result.matched_count == 0: return jsonify({'error': 'User not found'}), 404
        return jsonify({'message': 'Password reset successful for user'}), 200
    except Exception as e:
        return jsonify({'error': 'Invalid User ID or database error', 'details': str(e)}), 500

# --- Production Ready: No app.run() needed, Gunicorn handles it ---

