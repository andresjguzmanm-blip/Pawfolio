from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user, login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
import re
from sqlalchemy.exc import IntegrityError

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^\+?[\d\s\-()]{7,20}$")
ZIP_RE = re.compile(r"^[A-Za-z0-9\- ]{4,10}$")

app = Flask(__name__)
app.config["SECRET_KEY"] = "secret-and-long-password-=)"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///pawfolio.db"

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login" 

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    zipcode = db.Column(db.String(10), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route("/")
def inicio():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get("next")
            if next_page and next_page.startswith("/") and not next_page.startswith("//"):
                return redirect(next_page)
            return redirect(url_for("dashboard"))

        flash("Password or email may be incorrect", "error")

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    form={}

    if request.method == "POST":
        campos = ("first_name", "last_name", "email", "phone", "zipcode")
        form = {c: request.form.get(c, "").strip() for c in campos}
        form["email"] = form["email"].lower()
        password = request.form.get("password", "")

        errors = []
        if not form["first_name"]:
            errors.append("Write your name.")
        if not form["last_name"]:
            errors.append("Write your last name.")
        if not EMAIL_RE.match(form["email"]):
            errors.append("The email has an incorrect format")
        elif User.query.filter_by(email=form["email"]).first():
            errors.append("There is an account with that email")
        if not PHONE_RE.match(form["phone"]):
            errors.append("The phone number is not valid")
        if not ZIP_RE.match(form["zipcode"]):
            errors.append("The zipcode is not valid")
        if len(password) < 8:
            errors.append("The password must have at leat 8 characters")

        if errors:
            for e in errors:
                flash(e, "error")
        else:
            user = User(**form)
            user.set_password(password)
            db.session.add(user)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                flash("There is an account with that email", "error")
            else:
                login_user(user)
                return redirect(url_for("dashboard"))
    return render_template("newaccount.html", form=form)


@app.route("/dashboard")
@login_required
def dashboard():
    return f"Hi {current_user.first_name}! <a href='{url_for('logout')}'>Log out</a>"


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("inicio"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()      
    app.run(debug=True)
