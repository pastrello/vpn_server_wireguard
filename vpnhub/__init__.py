from flask import Flask
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect

from .config import Config
from .models import User, db

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Faça login para continuar."
login_manager.login_message_category = "warning"
csrf = CSRFProtect()
migrate = Migrate()


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)

    from .auth import bp as auth_bp
    from .routes import bp as main_bp
    from .sync import (
        format_bytes,
        handshake_age,
        peer_state,
        peer_state_label,
    )

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    @app.context_processor
    def inject_helpers():
        return {
            "peer_state": peer_state,
            "peer_state_label": peer_state_label,
            "format_bytes": format_bytes,
            "handshake_age": handshake_age,
        }

    return app
