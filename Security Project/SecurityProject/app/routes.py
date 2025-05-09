from flask import Blueprint, render_template, redirect, url_for, flash, request
from app import db, bcrypt
from app.models import User
from app.forms import CommentForm
from app.models import Comment
from flask import abort
import hashlib
import bleach
from sqlalchemy import text
from app.forms import RegisterForm, LoginForm
from flask_login import login_user, logout_user, login_required, current_user

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return redirect(url_for('main.login'))


@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # FIXED: Secure password hashing (bcrypt)
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        # VULNERABLE: MD5 password hashing 
        '''
        # This uses MD5, which is insecure and fast to crack
        hashed_pw = hashlib.md5(password.encode()).hexdigest()
        '''

        # FIXED: Secure registration using parameterized SQL
        sql = text("INSERT INTO user (username, password_hash) VALUES (:username, :password)")
        try:
            with db.engine.connect() as connection:
                connection.execute(sql, {"username": username, "password": hashed_pw})
                flash('Account created using secure SQL', 'success')
                return redirect(url_for('main.login'))
        except Exception as e:
            flash(f"SQL Error: {str(e)}", 'danger')

        # VULNERABLE: Registration using raw SQL Injection 
        '''
        # This is vulnerable because user input is directly embedded in the SQL
        username_safe = username.replace("'", "''")  # weak escaping, still vulnerable
        sql = f"INSERT INTO user (username, password_hash) VALUES ('{username_safe}', '{password}')"
        try:
            with db.engine.connect() as connection:
                connection.execute(text(sql))
                flash('Account created (SQL Injection vulnerable) ', 'warning')
                return redirect(url_for('main.login'))
        except Exception as e:
            flash(f"SQL Error: {str(e)}", 'danger')
        '''
   

    return render_template('register.html', form=form)


@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():

        # FIXED: Secure SQL query 
        sql = text("SELECT id, username, password_hash FROM user WHERE username = :username")
        result = db.session.execute(sql, {"username": form.username.data}).fetchone()

        # VULNERABLE: SQL Injection 
        '''
        sql = f"SELECT id, username, password_hash FROM user WHERE username = '{form.username.data}'"
        result = db.session.execute(text(sql)).fetchone()
        if result:
            user_id, username, password_hash = result
            user = User.query.get(user_id)
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Login failed. Invalid username or password.', 'danger')
        '''

        if result:
            user_id, username, password_hash = result
            user = User.query.get(user_id)

            # FIXED: Secure bcrypt password check
            if bcrypt.check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash('Login successful!', 'success')
                return redirect(url_for('main.dashboard'))

            # VULNERABLE: MD5 password check 
            '''
            input_pw = hashlib.md5(form.password.data.encode()).hexdigest()
            if user.password_hash == input_pw:
                login_user(user)
                flash('Login successful using MD5', 'warning')
                return redirect(url_for('main.dashboard'))
            '''
        else:
            flash('Login failed. Invalid username or password.', 'danger')

    return render_template('login.html', form=form)



@main.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = CommentForm()
    if form.validate_on_submit():
        # FIXED: Sanitize input to prevent XSS
        safe_content = bleach.clean(form.content.data)
        comment = Comment(content=safe_content, author=current_user)

        # VULNERABLE: No sanitization — allows XSS attacks
     #   comment = Comment(content=form.content.data, author=current_user)

        db.session.add(comment)
        db.session.commit()
        flash('Comment posted!', 'success')
        return redirect(url_for('main.dashboard'))

    comments = Comment.query.all()
    return render_template('dashboard.html', username=current_user.username, form=form, comments=comments)


@main.route('/admin')
@login_required
def admin():
    # Fixed Access Control (RBAC)
    if current_user.role != 'admin':
        abort(403)  # HTTP Forbidden
    return render_template('admin.html')

    # Vulnerable access control: no role check
    # return render_template('admin.html')

@main.app_errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('main.login'))
