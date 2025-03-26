from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, FileField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from flask_wtf.file import FileAllowed, FileRequired
from models import User

class RegisterForm(FlaskForm):
    """Form for user registration."""
    username = StringField('Username', validators=[
        DataRequired(), 
        Length(min=3, max=64, message='Username must be between 3 and 64 characters')
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message='Invalid email address'),
        Length(max=120)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken. Please choose a different one.')
            
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different one.')

class LoginForm(FlaskForm):
    """Form for user login."""
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class EncryptForm(FlaskForm):
    """Form for encrypting data."""
    input_type = SelectField(
        'Input Type', 
        choices=[
            ('text', 'Text/Keyword'),
            ('txt', 'Text File (.txt)'),
            ('pdf', 'PDF File (.pdf)'),
            ('voice', 'Voice File (.wav, .mp3)')
        ],
        validators=[DataRequired()]
    )
    text_input = TextAreaField('Text Input')
    file_input = FileField('File Input', validators=[
        FileAllowed(['txt', 'pdf', 'wav', 'mp3'], 'Only txt, pdf, wav, or mp3 files allowed!')
    ])
    submit = SubmitField('Encrypt')

class DecryptForm(FlaskForm):
    """Form for decrypting data."""
    data_id = SelectField('Select Encrypted Data', coerce=int, validators=[DataRequired()])
    master_key = StringField('Master Key', validators=[DataRequired()])
    submit = SubmitField('Decrypt')

class SearchForm(FlaskForm):
    """Form for searching encrypted data."""
    data_id = SelectField('Select Encrypted Data', coerce=int, validators=[DataRequired()])
    search_term = StringField('Search Term', validators=[DataRequired()])
    submit = SubmitField('Search')

class UpdateForm(FlaskForm):
    """Form for updating encrypted data."""
    data_id = SelectField('Select Encrypted Data', coerce=int, validators=[DataRequired()])
    input_type = SelectField(
        'Input Type', 
        choices=[
            ('text', 'Text/Keyword'),
            ('txt', 'Text File (.txt)'),
            ('pdf', 'PDF File (.pdf)'),
            ('voice', 'Voice File (.wav, .mp3)')
        ],
        validators=[DataRequired()]
    )
    text_input = TextAreaField('New Text Input')
    file_input = FileField('New File Input', validators=[
        FileAllowed(['txt', 'pdf', 'wav', 'mp3'], 'Only txt, pdf, wav, or mp3 files allowed!')
    ])
    master_key = StringField('Master Key', validators=[DataRequired()])
    submit = SubmitField('Update')
