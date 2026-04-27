
import os
import jwt
import datetime
import re
from functools import wraps
from flask import Flask, render_template, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

# .envファイルから環境変数を読み込む
load_dotenv()

# --- App Initialization & DB Configuration ---

app = Flask(__name__, static_folder='static', static_url_path='/static')
# 環境変数からSECRET_KEYを読み込む。なければデフォルト値を使うが、本番環境では必ず設定すること。
app.secret_key = os.environ.get('SECRET_KEY', 'a-default-fallback-key-that-is-not-secure')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Rate Limiting Setup ---
limiter = Limiter(
    get_remote_address, # Use the client's IP address as the key
    app=app,
    default_limits=["200 per day", "50 per hour"], # Default limits for all routes
    storage_uri="memory://", # In-memory storage for this example
)

db = SQLAlchemy(app)

# --- Database Model ---

class User(db.Model):
    """Represents a user in the database."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False) # Increased length for hash
    role = db.Column(db.String(80), nullable=False, default='viewer')

    def __repr__(self):
        return f'<User {self.username}>'

# --- Decorators ---

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            # Try to get token from Authorization header as well for best practice
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

        if not token:
            return jsonify({'message': '認証トークンが見つかりません。', 'success': False}), 401
        try:
            g.user = jwt.decode(token, app.secret_key, algorithms=["HS256"])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return jsonify({'message': 'トークンが無効か有効期限切れです', 'success': False}), 401
        return f(*args, **kwargs)
    return decorated

def admin_role_required(f):
    @wraps(f)
    @token_required
    def decorated_function(*args, **kwargs):
        if g.user.get('role') != 'admin':
            return jsonify({'message': 'この操作を行う権限がありません', 'success': False}), 403
        return f(*args, **kwargs)
    return decorated_function

# --- Custom Error Handler for Rate Limiting ---
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify(success=False, message="レートリミットを超えました。少し時間をおいてから再試行してください。" ), 429

# --- Route Definitions ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
@limiter.limit("10 per hour") # Also limit registration attempts
def register():
    data = request.get_json()
    username, password = data.get('username'), data.get('password')
    if not username or not password:
        return jsonify({'success': False, 'message': 'ユーザー名とパスワードは必須です'}), 400

    # --- Password complexity check ---
    errors = []
    if len(password) < 8:
        errors.append("8文字以上")
    if not re.search(r'[A-Z]', password):
        errors.append("大文字")
    if not re.search(r'[a-z]', password):
        errors.append("小文字")
    if not re.search(r'[0-9]', password):
        errors.append("半角数字")

    if errors:
        error_message = f"パスワードには、{'、'.join(errors)}を含める必要があります。"
        return jsonify({'success': False, 'message': error_message}), 400
    # --------------------------------

    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': 'このユーザー名は既に使用されています'}), 409
    
    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password, role='viewer')
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'success': True, 'message': '登録が完了しました。'}), 201

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute") # Specific rate limit for login
def login():
    data = request.get_json()
    username, password = data.get('username'), data.get('password')
    
    user = User.query.filter_by(username=username).first()

    if not (user and check_password_hash(user.password, password)):
        return jsonify({"success": False, "message": "IDまたはパスワードが違います。"}), 401

    token = jwt.encode({
        'user': user.username, 
        'role': user.role, 
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }, app.secret_key, algorithm="HS256")
    
    return jsonify({'success': True, 'token': token, 'role': user.role})
    
@app.route('/dashboard')
@token_required
def dashboard():
    return render_template('dashboard.html', role=g.user.get('role', '不明'))

@app.route('/admin')
@admin_role_required
def admin_area():
    users = User.query.order_by(User.id).all()
    return render_template('admin.html', users=users, current_admin_user=g.user)

# --- [追加] User Management API --- 

@app.route('/update_role', methods=['POST'])
@admin_role_required
def update_role():
    data = request.get_json()
    username, new_role = data.get('username'), data.get('role')

    if not all([username, new_role]) or new_role not in ['admin', 'viewer']:
        return jsonify({'success': False, 'message': '無効なリクエストです。'}), 400

    if username == g.user.get('user'):
        return jsonify({'success': False, 'message': '自身の役割は変更できません。'}), 403

    user_to_update = User.query.filter_by(username=username).first()
    if not user_to_update:
        return jsonify({'success': False, 'message': '対象ユーザーが見つかりません。'}), 404

    try:
        user_to_update.role = new_role
        db.session.commit()
        return jsonify({'success': True, 'message': f'{username}の役割を{new_role}に変更しました。'})
    except SQLAlchemyError:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'データベースの更新中にエラーが発生しました。'}), 500

@app.route('/delete_user', methods=['POST'])
@admin_role_required
def delete_user():
    data = request.get_json()
    username = data.get('username')

    if not username:
        return jsonify({'success': False, 'message': 'ユーザー名が必要です。'}), 400

    if username == g.user.get('user'):
        return jsonify({'success': False, 'message': '自分自身のアカウントは削除できません。'}), 403

    user_to_delete = User.query.filter_by(username=username).first()
    if not user_to_delete:
        return jsonify({'success': False, 'message': '対象ユーザーが見つかりません。'}), 404

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        return jsonify({'success': True, 'message': f'{username}を削除しました。'})
    except SQLAlchemyError:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'データベースの更新中にエラーが発生しました。'}), 500

# --- CLI Command ---

@app.cli.command('init-db')
def init_db_command():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        # 本番環境では環境変数から初期パスワードを読み込むことを推奨
        admin_password_plain = os.environ.get('ADMIN_PASSWORD', 'password')
        admin_password = generate_password_hash(admin_password_plain)
        admin_user = User(username='admin', password=admin_password, role='admin')
        db.session.add(admin_user)
        db.session.commit()
    print('Initialized the database and created admin user.')

# --- Main Execution ---

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    # FLASK_ENVが'development'でない限り、デバッグモードを無効化
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
