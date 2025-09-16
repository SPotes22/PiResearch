# app/__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import logging

db = SQLAlchemy()
migrate = Migrate()
from app.models import db


def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'super-secret-key'  # cambiar en prod
    app.config['JWT_EXP_DELTA_SECONDS'] = 3600  # 1 hora

    db.init_app(app)
    migrate.init_app(app, db)
    # create tables
    with app.app_context():
        db.create_all()


    # Logging
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s [%(levelname)s] %(message)s')

    from .routes import user_bp
    app.register_blueprint(user_bp, url_prefix='/api/v1')

    return app

