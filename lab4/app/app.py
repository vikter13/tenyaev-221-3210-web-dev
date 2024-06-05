from flask import Flask, render_template, session, request, redirect, url_for, flash, g
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import sqlite3
import hashlib
import re

# config
app = Flask(__name__)
application = app
app.config.from_pyfile('config.py')

# database
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def modify_db(query, args=()):
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
    cur.close()

# flask-login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "auth"
login_manager.login_message = "Войдите, чтобы просматривать содержимое данной страницы"
login_manager.login_message_category = "warning"

CREATE_USER_FIELDS = ['login', 'password', 'last_name', 'first_name', 'middle_name', 'role_id']
EDIT_USER_FIELDS = ['last_name', 'first_name', 'middle_name', 'role_id']

class User(UserMixin):
    def __init__(self, user_id, login):
        self.id = user_id
        self.login = login

# get roles
def get_roles():
    query = "SELECT * FROM roles"
    roles = query_db(query)
    return roles

# load user
@login_manager.user_loader
def load_user(user_id):
    query = "SELECT id, login FROM users WHERE id=?"
    user = query_db(query, (user_id,), one=True)
    if user:
        return User(user['id'], user['login'])
    return None

# routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/info')
def info():
    session['counter'] = session.get('counter', 0) + 1
    return render_template('info.html')

@app.route('/auth', methods=["GET", "POST"])
def auth():
    if request.method == "GET":
        return render_template("auth.html")
    
    login = request.form.get("login", "")
    password = request.form.get("pass", "")
    remember = request.form.get("remember") == "on"

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    query = 'SELECT id, login FROM users WHERE login=? AND password_hash=?'
    
    user = query_db(query, (login, password_hash), one=True)

    if user:
        login_user(User(user['id'], user['login']), remember=remember)
        flash("Успешная авторизация", category="success")
        target_page = request.args.get("next", url_for("index"))
        return redirect(target_page)

    flash("Введены некорректные учётные данные пользователя", category="danger")    
    return render_template("auth.html")

@app.route('/users')
def users():
    query = 'SELECT users.*, roles.name as role_name FROM users LEFT JOIN roles ON users.role_id = roles.id'
    data = query_db(query)
    return render_template("users.html", users=data)

# func for get form data
def get_form_data(required_fields):
    form_data = {}
    for field in required_fields:
        form_data[field] = request.form.get(field) or None
    return form_data

# continue routes
@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    roles = get_roles()
    user = query_db(query, (user_id,), one=True)

    if request.method == "POST":
        form_data = get_form_data(EDIT_USER_FIELDS)
        form_data['user_id'] = user_id
        query = ("UPDATE users SET last_name=?, first_name=?, middle_name=?, role_id=? WHERE id=?")
        try:
            modify_db(query, (form_data['last_name'], form_data['first_name'], form_data['middle_name'], form_data['role_id'], user_id))
            flash("Запись пользователя успешно обновлена", category="success")
            return redirect(url_for('users'))
        except sqlite3.DatabaseError as error:
            flash(f'Ошибка редактирования пользователя! {error}', category="danger")

    return render_template("edit_user.html", user=user, roles=roles)

@app.route('/user/<int:user_id>/delete', methods=["POST"])
@login_required
def delete_user(user_id):
    query = "DELETE FROM users WHERE id=?"
    try:
        modify_db(query, (user_id,))
        flash("Запись пользователя успешно удалена", category="success")
    except sqlite3.DatabaseError as error:
        flash(f'Ошибка удаления пользователя! {error}', category="danger")
    
    return redirect(url_for('users'))

@app.route('/users/new', methods=['GET', 'POST'])
@login_required
def create_user():
    roles = get_roles()
    user = {}
    errors = {}
    if request.method == 'POST':
        form_data = get_form_data(CREATE_USER_FIELDS)
        errors = validate_user_data(form_data['login'], form_data['password'], form_data['first_name'],
                                    form_data['last_name'])

        if not errors:
            form_data['password_hash'] = hashlib.sha256(form_data['password'].encode()).hexdigest()
            query = ("INSERT INTO users (login, password_hash, last_name, first_name, middle_name, role_id) "
                     "VALUES (?, ?, ?, ?, ?, ?)")
            try:
                modify_db(query, (
                form_data['login'], form_data['password_hash'], form_data['last_name'], form_data['first_name'],
                form_data['middle_name'], form_data['role_id']))
                return redirect(url_for('users'))
            except sqlite3.DatabaseError as error:
                flash(f'Ошибка создания пользователя! {error}', category="danger")
        else:
            flash("Пожалуйста, исправьте ошибки в форме.", category="danger")
        
    print(errors)
    return render_template("user_form.html", roles=roles, user=user, errors=errors)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not old_password or not new_password or not confirm_password:
            flash("Все поля должны быть заполнены", category="danger")
        elif new_password != confirm_password:
            flash("Новый пароль и подтверждение пароля не совпадают", category="danger")
        else:
            query = "SELECT password_hash FROM users WHERE id=?"
            user = query_db(query, (current_user.id,), one=True)
            if user and hashlib.sha256(old_password.encode()).hexdigest() == user['password_hash']:
                new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
                update_query = "UPDATE users SET password_hash=? WHERE id=?"
                try:
                    modify_db(update_query, (new_password_hash, current_user.id))
                    flash("Пароль успешно изменен", category="success")
                    return redirect(url_for('index'))
                except sqlite3.DatabaseError as error:
                    flash(f'Ошибка при изменении пароля! {error}', category="danger")
            else:
                flash("Неверный старый пароль", category="danger")
    
    return render_template('change_password.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route('/secret')
@login_required
def secret():
    return render_template('secret.html')

# close db connection after request
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# validation
def validate_user_data(login, password, first_name, last_name):
    errors = {}

    if not login:
        errors['login'] = "Поле логин не может быть пустым"
    if not password:
        errors['password'] = "Поле пароль не может быть пустым"
    if not first_name:
        errors['first_name'] = "Поле имя не может быть пустым"
    if not last_name:
        errors['last_name'] = "Поле фамилия не может быть пустым"
    
    if not re.match(r'^[a-zA-Z0-9]{5,}$', login):
        errors['login'] = "Логин должен состоять только из латинских букв и цифр и иметь длину не менее 5 символов"
    
    if len(password) < 8 or len(password) > 128:
        errors['password'] = "Пароль должен быть не менее 8 и не более 128 символов"
    if not re.search(r'[A-Z]', password):
        errors['password'] = "Пароль должен содержать как минимум одну заглавную букву"
    if not re.search(r'[a-z]', password):
        errors['password'] = "Пароль должен содержать как минимум одну строчную букву"
    if not re.search(r'[0-9]', password):
        errors['password'] = "Пароль должен содержать как минимум одну цифру"
    if re.search(r'\s', password):
        errors['password'] = "Пароль не должен содержать пробелов"
    if not re.match(r'^[a-zA-Z0-9~!?@#$%^&*_\-+()\[\]{}><\/\\|"\'.,:;]+$', password):
        errors['password'] = "Пароль содержит недопустимые символы"

    return errors
