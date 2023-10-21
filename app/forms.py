from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField, SelectField, FileField, FloatField
from wtforms.validators import DataRequired, EqualTo, Email


class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[Email(), DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    repeat_password = PasswordField('Password Repeat', validators=[EqualTo('password'), DataRequired()])
    remember = BooleanField("Remember me")
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField("Remember me")
    submit = SubmitField('Login')


class ProductsForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    price = FloatField('Product Price', validators=[DataRequired()])


class SettingsForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    photo = FileField('Photo')
    submit = SubmitField('Enter')