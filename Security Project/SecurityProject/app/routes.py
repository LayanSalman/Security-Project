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
        # Secure password hashing (bcrypt) 
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        # Insecure password hashing (MD5) 
        # hashed_pw = hashlib.md5(form.password.data.encode()).hexdigest()

        user = User(username=form.username.data, password_hash=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Account created. You can now log in.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user:
            # Secure bcrypt password check 
            if bcrypt.check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash('Login successful!', 'success')
                return redirect(url_for('main.dashboard'))

            # Insecure MD5 password check 
            # input_pw = hashlib.md5(form.password.data.encode()).hexdigest()
            # if user.password_hash == input_pw:
            #   login_user(user)
            #   flash('Login successful!', 'success')
            #   return redirect(url_for('main.dashboard'))

        flash('Login failed. Check credentials.', 'danger')
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
