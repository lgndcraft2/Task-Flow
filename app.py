from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from wtforms import StringField, SubmitField, PasswordField, EmailField, DateTimeLocalField, TextAreaField, SelectField
from wtforms_sqlalchemy.fields import QuerySelectField
from wtforms.validators import DataRequired, EqualTo, Email
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.validators import DataRequired, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from datetime import datetime, timedelta


app = Flask(__name__)
app.config["SECRET_KEY"] = 'qwertyasababyboy'
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://avnadmin:AVNS_wPcoMGUzftQFdfQhBnh@nafcourse-nasflask.e.aivencloud.com:19043/tasks"
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "connect_args": {"ssl": {"ssl-mode": "REQUIRED"}}
}

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=60)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))




class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=True)
    due_date = db.Column(db.DateTime, nullable=False)
    priority = db.Column(db.Enum('High', 'Medium', 'Low'), default='Low')
    status = db.Column(db.Enum('Pending', 'Completed'), default='Pending')

    user = db.relationship('User', backref=db.backref('tasks', lazy=True))
    category = db.relationship('Category', backref=db.backref('tasks', lazy=True))

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)


class AddTask(FlaskForm):
    title = StringField("Input Task Title Here...", validators=[DataRequired()])
    category = QuerySelectField('Category', query_factory=lambda: Category.query.all(), get_label='name', allow_blank=True)
    due_date = DateTimeLocalField("Due Date", format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    priority = SelectField('Priority', choices=[('High', 'High'), ('Medium', 'Medium'), ('Low', 'Low')], validators=[DataRequired()])
    submit = SubmitField("Submit")

class Register(FlaskForm):
    username = StringField("Input Fullname Here...", validators=[DataRequired()])
    email = EmailField('Input E-mail Here...', validators=[DataRequired()], render_kw={"autocomplete": "off"})
    password = PasswordField('Input Password Here...', validators=[DataRequired()], render_kw={"autocomplete": "off"})
    confirmPassword = PasswordField('Input Password Again...', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField("Submit")

class Login(FlaskForm):
    email = EmailField('Input E-mail Here...', validators=[DataRequired()], render_kw={"autocomplete": "off"})
    password = PasswordField('Input Password Here...', validators=[DataRequired()], render_kw={"autocomplete": "off"})
    submit = SubmitField("Submit")

@app.route('/')
def base():
    return render_template('index.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = AddTask()
    user = current_user
    tasks = Task.query.filter_by(user_id=current_user.id).all()  # Fetch user's tasks
    categories = Category.query.all()
    if form.validate_on_submit():
        print ("Stage 1.5")
        new_task = Task(
            title=form.title.data,
            category=form.category.data,
            due_date=form.due_date.data,
            priority=form.priority.data,
            user_id=current_user.id,
            status="Pending"
        )
        try:
            db.session.add(new_task)
            db.session.commit()
            flash('Task added successfully!', 'success')
            return redirect(url_for('dashboard'))  # Refresh dashboard
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while adding your task. Please try again.', 'danger')
            return redirect(url_for('dashboard'))

    return render_template('dashboard.html', form=form, tasks=tasks, user=user, categories=categories)

@app.route('/complete_task/<int:task_id>', methods=['POST'])
@login_required
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    if task.status != "Completed":  # Ensure we don't keep marking it
        task.status = "Completed"
        db.session.commit()
        flash('Task marked as completed!', 'success')

    return redirect(url_for('dashboard'))

@app.route('/edit_task/<int:task_id>', methods=['POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Check if the task belongs to the current user
    if task.user_id != current_user.id:
        flash('You do not have permission to edit this task.', 'danger')
        return redirect(url_for('dashboard'))
    
    if task.status == "Completed":
        flash('You cannot edit a completed task.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get form data
    title = request.form.get('title')
    category_id = request.form.get('category')
    due_date_str = request.form.get('due_date')
    priority = request.form.get('priority')
    
    # Convert the datetime string to a datetime object
    try:
        due_date = datetime.strptime(due_date_str, '%Y-%m-%dT%H:%M')
    except ValueError:
        flash('Invalid date format.', 'danger')
        return redirect(url_for('dashboard'))
        
    # Update task
    task.title = title
    
    # Handle category (could be empty)
    if category_id:
        category = Category.query.get(category_id)
        if category:
            task.category = category
        else:
            task.category = None
    else:
        task.category = None
    
    task.due_date = due_date
    task.priority = priority
    
    # Save changes
    db.session.commit()
    flash('Task updated successfully!', 'success')
    
    return redirect(url_for('dashboard'))

@app.route('/delete_task/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    db.session.delete(task)
    db.session.commit()
    flash('Task deleted successfully!', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = Register()
    if form.validate_on_submit():
        # Check if the username or email already exists
        existing_user = User.query.filter((User.username == form.username.data) | (User.email == form.email.data)).first()
        if existing_user:
            flash('Username or email already exists', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        try:
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while creating your account. Please try again.', 'danger')
            return redirect(url_for('register'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))  # Prevent infinite redirection loop

    form = Login()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))  # Redirect to dashboard after successful login
        else:
            flash('Invalid email or password', 'danger')

    return render_template('login.html', form=form)


@app.route("/forgot_password")
def forgot_password():
    return render_template('forgot_password.html')

@app.route("/logout")
@login_required
def log_out():
    logout_user()
    flash("You have been logged out")
    return redirect(url_for("login"))


# @app.errorhandler(404)
# def page_not_found(e):
#     if current_user.is_authenticated:
#         user = current_user
#     else:
#         return redirect(url_for('base'))
#     return render_template("404.html")

# @app.errorhandler(413)
# def page_not_found(e):
#     if current_user.is_authenticated:
#         user = current_user
#     else:
#         return redirect(url_for('base'))
#     return render_template("413.html")

# @app.errorhandler(500)
# def page_not_found(e):
#     if current_user.is_authenticated:
#         user = current_user
#     else:
#         return redirect(url_for('base'))
#     return render_template("500.html")

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)