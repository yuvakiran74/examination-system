from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import re
import os

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data', 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your-very-secret-key'  # Replace with a strong, random value in production

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'student' or 'faculty'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    if not os.path.exists('data'):
        os.makedirs('data')
    db.create_all()
    if not User.query.filter_by(username='LT0001').first():
        admin = User(username='LT0001', password=generate_password_hash('admin'), role='faculty')
        db.session.add(admin)
        db.session.commit()

@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.role == 'faculty':
            return redirect(url_for('faculty_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        role = request.form['role']
        password = request.form['password']
        if role == 'student':
            username = request.form['student_id']
            # Student ID validation
            student_pattern = r'^23KD1A05([0-9]{2}|[A-C][0-9]|[A-C][1-9]|[B-Q][0-9]|[B-Q][1-9])$'
            if not re.match(student_pattern, username):
                flash('Invalid student register number format.')
                return redirect(url_for('register'))
        elif role == 'faculty':
            username = request.form['faculty_id']
            # Faculty ID validation
            faculty_pattern = r'^LT[0-9]{4}$'
            if not re.match(faculty_pattern, username):
                flash('Invalid faculty ID format.')
                return redirect(url_for('register'))
        else:
            flash('Please select a role.')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('User already exists')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)
        user = User(username=username, password=hashed_password, role=role)
        db.session.add(user)
        db.session.commit()
        flash('Registered successfully! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        role = request.form['role']
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, role=role).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully')
            if role == 'faculty':
                return redirect(url_for('faculty_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid credentials or role')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out')
    return redirect(url_for('login'))

@app.route('/faculty_dashboard')
@login_required
def faculty_dashboard():
    if current_user.role != 'faculty':
        flash('Faculty only!')
        return redirect(url_for('login'))
    users = User.query.filter_by(role='student').all()
    return render_template('faculty_dashboard.html', users=users)

@app.route('/student_dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect(url_for('faculty_dashboard'))
    return render_template('student_dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)
