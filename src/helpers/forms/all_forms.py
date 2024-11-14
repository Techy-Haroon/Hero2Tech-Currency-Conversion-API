from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, Regexp
class SignupForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=20),
            Regexp(
                r"^[A-Za-z0-9_-]+$",
                message="Username can only contain letters, numbers, dashes, and underscores.",
            ),
        ],
        render_kw={"autocomplete": "username", "minlength": "3", "maxlength": "20"},
    )
    email = StringField(
        "Email",
        validators=[DataRequired(), Email(), Length(min=6, max=45)],
        render_kw={
            "type": "email",
            "autocomplete": "email",
            "minlength": "6",
            "maxlength": "45",
        },
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=8, max=25)],
        render_kw={
            "type": "password",
            "autocomplete": "new-password",
            "minlength": "8",
            "maxlength": "25",
        },
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), Length(min=8, max=25)],
        render_kw={
            "type": "password",
            "autocomplete": "new-password",
            "minlength": "8",
            "maxlength": "25",
        },
    )
    submit = SubmitField("Sign Up")


class CompleteSignupForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=20),
            Regexp(
                r"^[A-Za-z0-9_-]+$",
                message="Username can only contain letters, numbers, dashes, and underscores.",
            ),
        ],
        render_kw={"autocomplete": "username", "minlength": "3", "maxlength": "20"},
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=8, max=25)],
        render_kw={
            "type": "password",
            "autocomplete": "new-password",
            "minlength": "8",
            "maxlength": "25",
        },
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), Length(min=8, max=25)],
        render_kw={
            "type": "password",
            "autocomplete": "new-password",
            "minlength": "8",
            "maxlength": "25",
        },
    )
    submit = SubmitField("Complete Signup")


class LoginForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[DataRequired(), Email(), Length(min=6, max=45)],
        render_kw={
            "type": "email",
            "autocomplete": "email",
            "minlength": "6",
            "maxlength": "45",
        },
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=8, max=25)],
        render_kw={
            "type": "password",
            "autocomplete": "current-password",
            "minlength": "8",
            "maxlength": "25",
        },
    )
    remember_me = BooleanField("Remember me")
    submit = SubmitField("Log In")


class ForgotPasswordForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[DataRequired(), Email(), Length(min=6, max=45)],
        render_kw={
            "type": "email",
            "autocomplete": "email",
            "minlength": "6",
            "maxlength": "45",
        },
    )
    submit = SubmitField("Send Reset Link")


class EmailConfirmationForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[DataRequired(), Email(), Length(min=6, max=45)],
        render_kw={
            "type": "email",
            "autocomplete": "email",
            "minlength": "6",
            "maxlength": "45",
        },
    )
    submit = SubmitField("Resend Confirmation Email")


class ResetPasswordForm(FlaskForm):
    password = PasswordField(
        "New Password",
        validators=[DataRequired(), Length(min=8, max=25)],
        render_kw={"autocomplete": "new-password", "minlength": "8", "maxlength": "25"},
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), Length(min=8, max=25)],
        render_kw={"autocomplete": "new-password", "minlength": "8", "maxlength": "25"},
    )
    submit = SubmitField("Reset Password")


class UpdateProfileForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=20),
            Regexp(
                r"[A-Za-z0-9_-]+$",
                message="Username can only contain leters, numbers, dashes, and underscores.",
            ),
        ],
        render_kw={"autocomplete": "username", "minlength": "3", "maxlength": "20"},
    )
    submit = SubmitField("Update Profile")


class FeatureRequestForm(FlaskForm):
    name = StringField(
        "Name",
        validators=[
            DataRequired(),
            Length(min=3, max=20),
            Regexp(
                r"^(?!\s)[A-Za-z]+(?:\s[A-Za-z]+)*(?<!\s)$",
                message="Name must contain only alphabets, no leading/trailing spaces, and at least one alphabet.",
            ),
        ],
        render_kw={
            "type": "text",
            "autocomplete": "name",
            "pattern": "^(?!\s)[A-Za-z]+(?:\s[A-Za-z]+)*(?<!\s)$",
            "title": "Name must contain only alphabets, no leading/trailing spaces, and at least one alphabet.",
            "minlength": "3",
            "maxlength": "20",
        },
    )
    email = StringField(
        "Email",
        validators=[DataRequired(), Email(), Length(min=6, max=45)],
        render_kw={
            "type": "email",
            "autocomplete": "email",
            "minlength": "6",
            "maxlength": "45",
        },
    )
    message = TextAreaField(
        "Message",
        validators=[DataRequired(), Length(min=10, max=200)],
        render_kw={"minlength": "10", "maxlength": "200"},
    )
    submit = SubmitField("Submit Request")


class ReportProblemForm(FlaskForm):
    name = StringField(
        "Name",
        validators=[
            DataRequired(),
            Length(min=3, max=20),
            Regexp(
                r"^(?!\s)[A-Za-z]+(?:\s[A-Za-z]+)*(?<!\s)$",
                message="Name must contain only alphabets, no leading/trailing spaces, and at least one alphabet.",
            ),
        ],
        render_kw={
            "type": "text",
            "autocomplete": "name",
            "pattern": "^(?!\s)[A-Za-z]+(?:\s[A-Za-z]+)*(?<!\s)$",
            "title": "Name must contain only alphabets, no leading/trailing spaces, and at least one alphabet.",
            "minlength": "3",
            "maxlength": "20",
        },
    )
    email = StringField(
        "Email",
        validators=[DataRequired(), Email(), Length(min=6, max=45)],
        render_kw={
            "type": "email",
            "autocomplete": "email",
            "minlength": "6",
            "maxlength": "45",
        },
    )
    message = TextAreaField(
        "Message",
        validators=[DataRequired(), Length(min=10, max=200)],
        render_kw={"minlength": "10", "maxlength": "200"},
    )
    submit = SubmitField("Submit Report")


class ContactUsForm(FlaskForm):
    name = StringField(
        "Name",
        validators=[
            DataRequired(),
            Length(min=3, max=20),
            Regexp(
                r"^(?!\s)[A-Za-z]+(?:\s[A-Za-z]+)*(?<!\s)$",
                message="Name must contain only alphabets, no leading/trailing spaces, and at least one alphabet.",
            ),
        ],
        render_kw={
            "type": "text",
            "autocomplete": "name",
            "pattern": "^(?!\s)[A-Za-z]+(?:\s[A-Za-z]+)*(?<!\s)$",
            "title": "Name must contain only alphabets, no leading/trailing spaces, and at least one alphabet.",
            "minlength": "3",
            "maxlength": "20",
        },
    )
    email = StringField(
        "Email",
        validators=[DataRequired(), Email(), Length(min=6, max=45)],
        render_kw={
            "type": "email",
            "autocomplete": "email",
            "minlength": "6",
            "maxlength": "45",
        },
    )
    message = TextAreaField(
        "Message",
        validators=[DataRequired(), Length(min=10, max=200)],
        render_kw={"minlength": "10", "maxlength": "200"},
    )
    submit = SubmitField("Send Message")