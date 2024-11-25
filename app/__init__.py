from flask import Flask, request, render_template
from app.routes.auth import auth_bp
from app.routes.haproxy import haproxy_bp
from datetime import timedelta

def create_app():
    app = Flask(__name__)
    app.secret_key = 'f7d3814dd7f44e6ab8ff23c98a92c7fc'

    # Konfigurasi tambahan untuk session
    app.config['SESSION_COOKIE_NAME'] = 'auth_session'
    app.config['SESSION_PERMANENT'] = False
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=300)

    # Daftarkan blueprint
    app.register_blueprint(auth_bp)
    app.register_blueprint(haproxy_bp)

    @app.errorhandler(404)
    def not_found_error(error):
        previous_page = request.referrer if request.referrer else '/'
        return render_template('errors/404.html', previous_page=previous_page), 404

    @app.errorhandler(500)
    def internal_error(error):
        previous_page = request.referrer if request.referrer else '/'
        return render_template('errors/500.html', previous_page=previous_page), 500

    return app
