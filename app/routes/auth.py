from flask import Blueprint, jsonify, render_template, request, url_for, session, redirect, make_response
from werkzeug.security import check_password_hash, generate_password_hash
from app.utils.file_ops import is_user_exist, save_users
from app.utils.security import SECRET_KEY
import jwt, datetime

auth_bp = Blueprint('auth', __name__)


@auth_bp.route("/", methods=["GET", "POST"])
def index():
    if session.get('logged_in'):
        return '<script>alert("Forbidden access"); window.location.href = "/home";</script>'

    is_user = is_user_exist()

    if request.method == "POST":
        data = request.get_json()

        if not data or 'username' not in data or 'password' not in data:
            return make_response('Missing credentials', 400)

        username = data['username']
        password = data['password']

        # if username in is_user and is_user[username]['password'] == password:
        if username in is_user and check_password_hash(is_user[username]['password'], password):
            # session.permanent = True
            session['logged_in'] = True
            session['username'] = username
            token = jwt.encode({
                'user': username,
                'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=600)
            },
            SECRET_KEY, algorithm="HS256")

            return jsonify({
                'message': True,
                'token': token
            })
        else:
            return jsonify({'message': False}), 401

    return render_template('index.html')


@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.index'))


@auth_bp.route("/reset_password", methods=['GET', 'POST'])
def reset_password():
    if not session.get('logged_in'):
        return '<script>alert("You must login or session time has been expired"); window.location.href = "/";</script>'
    
    is_user = is_user_exist()
    username = session.get('username')

    if username not in is_user:
        return '<script>alert("User not found"); window.location.href = "/";</script>'

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        password_confirmation = request.form.get('password_confirmation')

        if not new_password or not password_confirmation:
            return '<script>alert("Please fill your password"); window.location.href = "/reset_password";</script>'

        if new_password == password_confirmation:
            hashed_password = generate_password_hash(new_password)
            is_user[username]['password'] = hashed_password
            save_users(is_user)
            session.clear()
            return '<script>alert("The password has been reset"); window.location.href = "/";</script>'
        else:
            return '<script>alert("Password not matches"); window.location.href = "/reset_password";</script>'
    
    return render_template('reset_password.html')