import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, flash, redirect, url_for,session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, DateTime, Boolean
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, PasswordField, SubmitField,TelField,SelectField,DateField,TextAreaField
from wtforms.validators import DataRequired, Length, Email, Regexp
import secrets
from datetime import timedelta
from flask_mail import Mail, Message
from flask_dance.contrib.google import make_google_blueprint, google
from oauthlib.oauth2.rfc6749.errors import TokenExpiredError

load_dotenv()  


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable not set!")
app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT"))
app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS") == 'True'
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
mail = Mail(app)
 
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DB_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
try:
    with app.app_context():
        db.engine.execute("SELECT 1")
    print("Database connected successfully!")
except Exception as e:
    print("Database connection failed:", e)
 
google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ],
    redirect_to="google_login",
    offline=True
)
app.register_blueprint(google_bp, url_prefix="/login")
 
class User(db.Model):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True)
    email = Column(String(100), unique=True, nullable=False)
    name = Column(String(50), nullable=False)
    password_hash = Column(String(512), nullable=True)
    provider = Column(String(20), nullable=True, default="LOCAL")
    google_id = Column(String(100), nullable=True)
    email_verified = Column(Boolean, default=False, nullable=False)
    reset_token = Column(String(100), nullable=True)
    reset_token_expires = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

class Booking(db.Model):
    __tablename__ = "bookings"
    
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    session_type = db.Column(db.String(50), nullable=False)
    session_date = db.Column(db.Date, nullable=False)
    location = db.Column(db.String(150), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
# ----------------- Form -----------------
class SignupForm(FlaskForm):
    name = StringField(
        "Name",
        validators=[
            DataRequired(message="Name is required"),
            Length(min=3, max=50, message="Name must be 3-50 characters"),
            Regexp('^[A-Za-z ]+$', message="Name can only contain letters and spaces")
        ]
    )
    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=6, message="Password must be at least 6 characters"),
            Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$',
                message="Password must have at least one uppercase, one lowercase, one number, and one special character"
            )
        ]
    )
    submit = SubmitField("Register")


class BookingForm(FlaskForm):
    full_name = StringField("Full Name", validators=[DataRequired(), Length(max=100)])
    email = EmailField("Email", validators=[DataRequired(), Email(), Length(max=100)])
    phone_number = TelField("Phone Number", validators=[DataRequired(), Length(max=20)])
    session_type = SelectField("Session Type", 
                               choices=[("", "Session Type"), 
                                        ("Wedding", "Wedding"), 
                                        ("Pre-Wedding", "Pre-Wedding"), 
                                        ("Portrait", "Portrait"),
                                        ("Event", "Event"),
                                        ("Product", "Product")],
                               validators=[DataRequired()])
    session_date = DateField("Date", validators=[DataRequired()])
    location = StringField("Location / Venue", validators=[DataRequired(), Length(max=150)])
    notes = TextAreaField("Additional Notes")
    submit = SubmitField("Submit Booking")

class ForgotPasswordForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Send Reset Link")

class ResetPasswordForm(FlaskForm):
    password = PasswordField(
        "New Password",
        validators=[
            DataRequired(),
            Length(min=6),
            Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$',
                message="Password must have at least one uppercase, one lowercase, one number, and one special character"
            )
        ]
    )
    submit = SubmitField("Reset Password")
 
from flask import redirect, url_for

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/gallery/")
def gallery_page():
    print(url_for('gallery_page'))  # T
    return render_template("gallery.html")
@app.route("/about/")
def about_page():
    return render_template("about.html")

@app.route("/google-login")
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))

    try:
        resp = google.get("/oauth2/v2/userinfo")
        resp.raise_for_status()
    except TokenExpiredError:
        
        session.pop("google_oauth_token", None)
        flash("Session expired, please log in again.", "warning")
        return redirect(url_for("google.login"))
    except Exception as e:
        flash(f"Failed to log in with Google: {str(e)}", "error")
        return redirect(url_for("login_page"))

    info = resp.json()
    email = info.get("email")
    name = info.get("name", email.split("@")[0])
    google_id = info.get("id")

    
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(
            email=email,
            name=name,
            provider="GOOGLE",
            google_id=google_id,
            email_verified=True
        )
        db.session.add(user)
        db.session.commit()

     
    session["user_id"] = user.id
    flash(f"Logged in successfully as {user.name} via Google!", "success")
    
    return redirect(url_for("book_session"))

 


@app.route("/signup", methods=["GET", "POST"])
def signup_page():
    form = SignupForm()
    switch_to_signin = False   

    if form.validate_on_submit():
        
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("User with this email already exists!", "error")
        else:
            new_user = User(
                name=form.name.data,
                email=form.email.data,
                provider="LOCAL"
            )
            new_user.set_password(form.password.data)
            db.session.add(new_user)
            db.session.commit()
            flash("User registered successfully!", "success")
            switch_to_signin = True   
     
            form.name.data = ""
            form.email.data = ""
            form.password.data = ""

    return render_template("form.html", form=form, switch_to_signin=switch_to_signin)


@app.route("/login", methods=["GET","POST"])
def login_page():
    form = BookingForm()
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            flash("Logged in successfully!", "success")
        else:
            flash("Invalid email or password", "error")
    return render_template("booking_popup.html", form=form)
 
def generate_reset_token():
    return secrets.token_urlsafe(32)


 
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user or user.reset_token_expires < datetime.utcnow():
        flash("Invalid or expired token!", "error")
        return redirect(url_for("login_page"))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        user.reset_token = None
        user.reset_token_expires = None
        db.session.commit()
        flash("Password has been reset successfully!", "success")
        return redirect(url_for("login_page"))

    return render_template("reset_password.html", form=form)
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = generate_reset_token()
            user.reset_token = token
            user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            
            reset_url = url_for('reset_password', token=token, _external=True)
            
            
            msg = Message(
                "Password Reset",
                sender="ortizzphotography0@gmail.com",
                recipients=[user.email]
            )
            
            
            msg.html = f"""
            <p>Hello {user.name},</p>
            <p>You requested a password reset. Click the link below to reset your password:</p>
            <p><a href="{reset_url}" style="background-color:#4CAF50;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;">Reset Your Password</a></p>
            <p>If you did not request this, you can ignore this email.</p>
            """
            mail.send(msg)
            print(f"Password reset email sent to {user.email}")

        flash("If this email exists, a reset link has been sent.", "info")
    return render_template("forgot_password.html", form=form)

@app.route("/book-session", methods=["GET", "POST"])
def book_session():
    form = BookingForm()
    if form.validate_on_submit():
        
        new_booking = Booking(
            full_name=form.full_name.data,
            email=form.email.data,
            phone_number=form.phone_number.data,
            session_type=form.session_type.data,
            session_date=form.session_date.data,
            location=form.location.data,
            notes=form.notes.data
        )
        db.session.add(new_booking)
        db.session.commit()
        flash("Your booking has been submitted successfully!", "success")
        return redirect(url_for("home"))

    return render_template("booking_popup.html", form=form)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
