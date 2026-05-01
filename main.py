
import os
import jwt
import datetime
import re
import random
from functools import wraps
from flask import Flask, render_template, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from faker import Faker

# .envファイルから環境変数を読み込む
load_dotenv()

# --- Faker Initialization ---
fake = Faker()

# --- App Initialization & DB Configuration ---

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.secret_key = os.environ.get('SECRET_KEY', 'a-default-fallback-key-that-is-not-secure')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Rate Limiting Setup ---
limiter = Limiter(
    get_remote_address, 
    app=app,
    default_limits=["200 per day", "50 per hour"], 
    storage_uri="memory://", 
)

db = SQLAlchemy(app)

# --- Database Model ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(80), nullable=False, default='viewer')

    def __repr__(self):
        return f'<User {self.username}>'

# --- Decorators ---

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token') or request.headers.get('Authorization', '').split(' ')[-1]
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

# --- Custom Error Handler ---
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify(success=False, message="レートリミットを超えました。少し時間をおいてから再試行してください。" ), 429

# --- Route Definitions ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
@limiter.limit("10 per hour")
def register():
    data = request.get_json()
    username, password = data.get('username'), data.get('password')
    if not username or not password:
        return jsonify({'success': False, 'message': 'ユーザー名とパスワードは必須です'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': 'このユーザー名は既に使用されています'}), 409
    
    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password, role='viewer')
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'success': True, 'message': '登録が完了しました。'}), 201

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
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

# --- 新しいハッキング演出ページへのルート（認証不要） ---
@app.route('/debug/leak')
def debug_leak():
    return render_template('dashboard_leak.html')
# -----------------------------------------------------

@app.route('/admin')
@admin_role_required
def admin_area():
    users = User.query.order_by(User.id).all()
    return render_template('admin.html', users=users, current_admin_user=g.user)

# --- User Management API --- 

@app.route('/update_role', methods=['POST'])
@admin_role_required
def update_role():
    data = request.get_json()
    username, new_role = data.get('username'), data.get('role')
    if not all([username, new_role]) or new_role not in ['admin', 'viewer']:
        return jsonify({'success': False, 'message': '無効なリクエストです。'}), 400
    user_to_update = User.query.filter_by(username=username).first()
    if not user_to_update or username == g.user.get('user'):
        return jsonify({'success': False, 'message': '不正な操作です。'}), 403
    user_to_update.role = new_role
    db.session.commit()
    return jsonify({'success': True, 'message': f'{username}の役割を{new_role}に変更しました。'})

@app.route('/delete_user', methods=['POST'])
@admin_role_required
def delete_user():
    data = request.get_json()
    username = data.get('username')
    if not username or username == g.user.get('user'):
        return jsonify({'success': False, 'message': '不正な操作です。'}), 403
    user_to_delete = User.query.filter_by(username=username).first()
    if not user_to_delete:
        return jsonify({'success': False, 'message': '対象ユーザーが見つかりません。'}), 404
    db.session.delete(user_to_delete)
    db.session.commit()
    return jsonify({'success': True, 'message': f'{username}を削除しました。'})

# --- CLI Command ---

@app.cli.command('init-db')
def init_db_command():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin_password = os.environ.get('ADMIN_PASSWORD', 'password')
        admin_user = User(username='admin', password=generate_password_hash(admin_password), role='admin')
        db.session.add(admin_user)
        db.session.commit()
    print('Initialized the database and created admin user.')

# --- Main Execution ---

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
