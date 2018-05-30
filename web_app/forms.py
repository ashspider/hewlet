from flask.ext.wtf import Form
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
from wtforms.validators import InputRequired, Email


class LoginForm(Form):
    """Loginform """
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


class SignupForm(Form):
    """SignupForm """
    email = StringField('Email Address', [InputRequired("Please enter your email address."), Email("This field requires a valid email address")] ) 
    username = StringField('Username', [InputRequired("Please enter your name.")])
    password = PasswordField('Password',[InputRequired("Password required")])
