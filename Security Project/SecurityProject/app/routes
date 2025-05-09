def register():
    form = RegisterForm()
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # Secure registration (Default implementation)
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password_hash=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('main.login'))
         # Secure registration (Default implementation)
        
        '''
        # Vulnerable registration (Uncomment to enable vulnerability)
        username_safe = username.replace("'", "''")
        sql = f"INSERT INTO user (username, password_hash) VALUES ('{username_safe}', '{password}')"
        try:
             with db.engine.connect() as connection:
                 connection.execute(text(sql))
                 flash('Account created successfully!', 'success')
                 return redirect(url_for('main.login'))
        except Exception as e:
            flash(f"SQL Error: {str(e)}", 'danger')
        '''
    return render_template('register.html', form=form)
    
@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Secure login (Default implementation)
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Login failed. Invalid username or password.', 'danger')
          # Secure login (Default implementation)

        '''
        # Vulnerable login (Uncomment to enable vulnerability)
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
    return render_template('login.html', form=form)
