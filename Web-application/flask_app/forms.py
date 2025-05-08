from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, ValidationError
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    username = StringField('Username',validators=[DataRequired(message="Username is required")])
    totp = StringField('TOTP',validators=[DataRequired(message="TOTP is required")])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username',validators=[DataRequired(message="Username is required")])
    submit = SubmitField('Register')

class TOTPForm(FlaskForm):
    totp = StringField('TOTP',validators=[DataRequired(message="TOTP is required")])
    submit = SubmitField('Verify')

class RecoveryForm(FlaskForm):
    username = StringField('Username',validators=[DataRequired(message="Username is required")])
    submit = SubmitField('Next')
    
class MnemonicForm(FlaskForm):
    word1 = StringField('Word 1',validators=[DataRequired(message="Word is required")])
    word2 = StringField('Word 2',validators=[DataRequired(message="Word is required")])
    word3 = StringField('Word 3',validators=[DataRequired(message="Word is required")])
    word4 = StringField('Word 4',validators=[DataRequired(message="Word is required")])
    word5 = StringField('Word 5',validators=[DataRequired(message="Word is required")])
    word6 = StringField('Word 6',validators=[DataRequired(message="Word is required")])
    word7 = StringField('Word 7',validators=[DataRequired(message="Word is required")])
    word8 = StringField('Word 8',validators=[DataRequired(message="Word is required")])
    word9 = StringField('Word 9',validators=[DataRequired(message="Word is required")])
    word10 = StringField('Word 10',validators=[DataRequired(message="Word is required")])
    word11 = StringField('Word 11',validators=[DataRequired(message="Word is required")])
    word12 = StringField('Word 12',validators=[DataRequired(message="Word is required")])
    submit = SubmitField('Submit')