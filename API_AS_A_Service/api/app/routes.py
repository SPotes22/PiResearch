# app/routes.py
from flask import Blueprint, request, jsonify, current_app
from .models import User
from .schemas import UserSchema
from . import db
from functools import wraps
import jwt
from datetime import datetime, timedelta
import logging

user_bp = Blueprint('user', __name__)
user_schema = UserSchema()
user_list_schema = UserSchema(many=True)

# --- Decorador de autenticación ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'error': 'Token missing'}), 401
        try:
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

# --- Endpoints ---
@user_bp.route('/user', methods=['POST'])
def create_user():
    try:
        data = request.get_json()
        validated_data = user_schema.load(data)
    except Exception as e:
        logging.warning(f"Validation error: {e}")
        return jsonify({'error': str(e)}), 400

    if User.query.filter_by(username=validated_data['username']).first():
        return jsonify({'error': 'Username already exists'}), 409

    user = User(username=validated_data['username'])
    user.set_password(validated_data['password'])
    db.session.add(user)
    db.session.commit()
    logging.info(f"User created: {user.username}")
    return jsonify({'message': 'User created successfully'}), 201

@user_bp.route('/user', methods=['GET'])
@token_required
def get_users():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    users = User.query.paginate(page=page, per_page=per_page, error_out=False)
    result = user_list_schema.dump(users.items)
    return jsonify({
        'users': result,
        'total': users.total,
        'pages': users.pages,
        'current_page': users.page
    })

@user_bp.route('/user/<int:id>', methods=['PUT'])
@token_required
def update_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    data = request.get_json()
    if 'password' in data:
        user.set_password(data['password'])
    if 'username' in data:
        user.username = data['username']
    db.session.commit()
    logging.info(f"User updated: {user.username}")
    return jsonify({'message': 'User updated successfully'})

@user_bp.route('/user/<int:id>', methods=['DELETE'])
@token_required
def delete_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    db.session.delete(user)
    db.session.commit()
    logging.info(f"User deleted: {user.username}")
    return jsonify({'message': 'User deleted successfully'})

@user_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()
    if not user or not user.check_password(data.get('password')):
        return jsonify({'error': 'Invalid credentials'}), 401
    payload = {
        'username': user.username,
        'exp': datetime.utcnow() + timedelta(seconds=current_app.config['JWT_EXP_DELTA_SECONDS'])
    }
    token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
    logging.info(f"User logged in: {user.username}")
    return jsonify({'token': token})

