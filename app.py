from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # client, worker, admin

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(100), default='Pending')

class Update(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))
    worker_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    image_path = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Query(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=True)  # Admin/Worker response
    solved = db.Column(db.Boolean, default=False)  # New column to track if query is resolved
    image_path = db.Column(db.String(200), nullable=True)  # Image for query
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/create_project', methods=['GET', 'POST'])
def create_project():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))  # Restrict access to Admins only

    clients = User.query.filter_by(role='client').all()  # Fetch all clients

    if request.method == 'POST':
        project_name = request.form.get('project_name')
        client_id = request.form.get('client_id')
        if not project_name or not client_id:
            flash('Please fill all fields', 'danger')
            return redirect(url_for('create_project'))

        new_project = Project(name=project_name, client_id=int(client_id))
        db.session.add(new_project)
        db.session.commit()
        flash('Project created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('create_project.html', clients=clients)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not check_password_hash(user.password, password):
            flash('Incorrect username or password. Please try again.', 'danger')
            return redirect(url_for('login'))

        session['user_id'] = user.id
        session['role'] = user.role

        flash(f"Welcome back, {user.username}!", "success")

        if user.role == 'client':
            return redirect(url_for('client_dashboard'))
        elif user.role == 'worker':
            return redirect(url_for('worker_dashboard'))
        elif user.role == 'admin':
            return redirect(url_for('admin_dashboard'))

    return render_template('login.html')


import re

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')

        if not username or not password or not role:
            flash('Please fill all fields', 'danger')
            return redirect(url_for('register'))

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already taken. Choose a different one.', 'danger')
            return redirect(url_for('register'))

        # Password strength validation
        if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"\d", password) or not re.search(r"[!@#$%^&*]", password):
            flash("Password must be at least 8 characters long, contain an uppercase letter, a number, and a special character.", "danger")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/client_dashboard')
def client_dashboard():
    if 'user_id' not in session or session.get('role') != 'client':
        flash("Access Denied!", "danger")
        return redirect(url_for('login'))
    projects = Project.query.filter_by(client_id=session['user_id']).all()
    return render_template('client_dashboard.html', projects=projects)

@app.route('/worker_dashboard', methods=['GET', 'POST'])
def worker_dashboard():
    if 'user_id' not in session or session.get('role') != 'worker':
        flash("Access Denied!", "danger")
        return redirect(url_for('login'))

    projects = Project.query.all()
    queries = Query.query.all()
    updates = Update.query.all()  # Ensure updates are fetched

    if request.method == 'POST':
        project_id = request.form.get('project_id')
        file = request.files.get('image')

        if file and project_id:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            new_update = Update(project_id=int(project_id), worker_id=session['user_id'], image_path=filename)
            db.session.add(new_update)
            db.session.commit()
            flash("Image uploaded successfully!", "success")
            return redirect(url_for('worker_dashboard'))

    # ✅ Ensure the function always returns a response
    return render_template('worker_dashboard.html', projects=projects, queries=queries, updates=updates)


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Access Denied!", "danger")
        return redirect(url_for('login'))
    projects = Project.query.all()
    users = User.query.all()
    queries = Query.query.all()
    return render_template('admin_dashboard.html', projects=projects, users=users, queries=queries)

@app.route('/update_user/<int:user_id>', methods=['GET', 'POST'])
def update_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Access Denied!", "danger")
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form.get('username')
        password = request.form.get('password')
        if password:
            user.password = generate_password_hash(password)
        user.role = request.form.get('role')
        db.session.commit()
        flash("User details updated successfully!", "success")
        return redirect(url_for('admin_dashboard'))
    
    return render_template('update_user.html', user=user)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Access Denied!", "danger")
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully!", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/project/<int:project_id>')
def project_status(project_id):
    project = Project.query.get_or_404(project_id)
    updates = Update.query.filter_by(project_id=project_id).all()
    return render_template('project_status.html', project=project, updates=updates)

@app.route('/queries', methods=['GET', 'POST'])
def queries():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_role = session.get('role')
    
    if user_role == 'client':
        projects = Project.query.filter_by(client_id=session['user_id']).all()
        queries = Query.query.filter_by(client_id=session['user_id']).all()
    elif user_role == 'admin' or user_role == 'worker':
        projects = Project.query.all()
        queries = Query.query.all()
    else:
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        project_id = request.form.get('project_id')
        message = request.form.get('message')
        file = request.files.get('image')

        if not project_id or not message:
            flash("Please select a project and enter a message.", "danger")
            return redirect(url_for('queries'))

        image_filename = None
        if file:
            image_filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            file.save(file_path)

        new_query = Query(project_id=int(project_id), client_id=session['user_id'], message=message, image_path=image_filename)
        db.session.add(new_query)
        db.session.commit()
        flash("Query submitted successfully!", "success")
        return redirect(url_for('queries'))

    return render_template('queries.html', queries=queries, projects=projects)

@app.route('/resolve_query/<int:query_id>', methods=['POST'])
def resolve_query(query_id):
    if 'user_id' not in session or session.get('role') not in ['admin', 'worker']:
        return redirect(url_for('login'))

    query = Query.query.get_or_404(query_id)
    response = request.form.get('response')

    if not response:
        flash("Please provide a response.", "danger")
        return redirect(url_for('queries'))

    query.response = response
    if session.get('role') == 'admin':
        query.solved = True  # Only admin can mark as solved

    db.session.commit()
    flash("Response submitted successfully!", "success")
    return redirect(url_for('queries'))


@app.route('/delete_query/<int:query_id>', methods=['POST'])
def delete_query(query_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    query = Query.query.get_or_404(query_id)
    if not query.solved:
        flash("Only solved queries can be deleted.", "danger")
        return redirect(url_for('queries'))
    
    db.session.delete(query)
    db.session.commit()
    flash("Query deleted successfully!", "success")
    return redirect(url_for('queries'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)