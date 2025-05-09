from flask_wtf import FlaskForm
from wtforms import TextAreaField
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    #Secure
    # password = PasswordField('Password', validators=[DataRequired()])

    #InSecure
    password = StringField('Password')  # Removed DataRequired
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    #Secure
    #password = PasswordField('Password', validators=[DataRequired()])
    
    #InSecure
    password = StringField('Password')  # Removed DataRequired
    submit = SubmitField('Login')

class CommentForm(FlaskForm):
    content = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Post')
