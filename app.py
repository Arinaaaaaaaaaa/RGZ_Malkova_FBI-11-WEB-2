from db import db
from db.models import Users, Advertisements
from sqlalchemy import func
from flask_login import login_user, login_required, current_user, logout_user, LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash, session
import re

app = Flask(__name__)

app.secret_key = "123"
user_db = "arina"
host_ip = "127.0.0.1"
host_port = "5432"
database_name = "rgz_arina"
password="123"

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{user_db}:{password}@{host_ip}:{host_port}/{database_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

login_manager = LoginManager(app)

login_manager.login_view = "login"
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


# Главная страница
@app.route('/index', methods=['GET', 'POST'])
def index():
    desk = Advertisements.query.all()
    return render_template('index.html', desk=desk)

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    name_user = Users.query.filter_by(username=current_user.username).first()
    adv = Advertisements.query.filter_by(author_id=name_user.id).all()
    return render_template('account.html', name_user=name_user, adv=adv)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username_form = request.form.get("username")
    password_form = request.form.get("password")
    name_form = request.form.get("text_name")
    avatar_form = request.form.get("avatar")
    contact_form = request.form.get("contact")
    about_form = request.form.get("about")

    isUserExist = Users.query.filter_by(username=username_form).first()

    errors = []

    if isUserExist:
        errors.append("Такой пользователь уже существует!")
    elif not username_form:
        errors.append("Введите имя пользователя!")
    elif not password_form:
        errors.append("Введите пароль!")
    elif not re.match("^[a-zA-Z0-9]+$", password_form):
        errors.append("Пароль должен содержать только буквы и цифры!")
    elif re.search("[а-яА-Я]", password_form):
        errors.append("Пароль не должен содержать русские буквы!")
    elif len(password_form) < 5:
        errors.append("Пароль должен содержать не менее 5 символов!")
    elif len(about_form) > 120:
        errors.append("Описание должно содержать не более 120 символов!")

    if errors:
        return render_template("register.html", errors=errors)

    hashedPswd = generate_password_hash(password_form, method="pbkdf2")
    newUser = Users(username=username_form, password=hashedPswd, name=name_form, avatar=avatar_form, contact=contact_form, about=about_form)

    db.session.add(newUser)
    db.session.commit()

    return redirect("/login")


# Страница авторизации
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    if current_user.is_authenticated:  # Если пользователь уже авторизован, перенаправляем его на другую страницу
        return redirect(url_for('index'))

    if request.method == "POST":
        errors = []
        username_form = request.form.get("username")
        password_form = request.form.get("password")

        my_user = Users.query.filter_by(username=username_form).first()

        if my_user is not None:
            if check_password_hash(my_user.password, password_form):
                login_user(my_user, remember=False)
                return redirect(url_for('index'))

        if not (username_form or password_form):
            errors.append("Введите имя пользователя и пароль!")
        elif my_user is None or not check_password_hash(my_user.password, password_form):
            errors.append("Неверное имя пользователя или пароль!")

        return render_template("login.html", errors=errors)

    return render_template("login.html")


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        subject_form = request.form['subject']
        main_text_form = request.form['main_text']
        author = Users.query.filter_by(username=current_user.username).first()
        email_form = request.form['email']
        photo_form = request.form['photo']
        max_id = db.session.query(func.max(Advertisements.id)).scalar()
        id_adv = 1

        if max_id is not None:
            id_adv = max_id + 1
            
        new_adv = Advertisements(id=id_adv, subject=subject_form, main_text=main_text_form, author_id=author.id, 
                                 author_name=author.name, email=email_form, photo=photo_form)
        db.session.add(new_adv)
        db.session.commit()

        return redirect(url_for('account'))

    return render_template('create_adv.html')


@app.route('/edit', methods=['GET', 'POST'])
@login_required
def edit():
    errors = []
    advertisements = Advertisements.query.filter_by(author_id=current_user.id).all()
    if request.method == 'POST':
        id_form = request.form['id']
        edit_adv = Advertisements.query.get(id_form)
        if edit_adv.author_id != current_user.id:
            errors.append("У вас нет прав для редактирования данного объявления!")
            return render_template("edit_u.html", errors = errors, advertisements=advertisements)
        
        edit_adv.subject = request.form['subject']
        edit_adv.main_text = request.form['main_text']
        edit_adv.email = request.form['email']
        edit_adv.photo = request.form['photo']
        db.session.commit()
        return redirect(url_for('account'))

    return render_template('edit_u.html', advertisements=advertisements)


@app.route('/delete', methods=['GET', 'POST'])
@login_required
def delete():
    errors = []
    advertisements = Advertisements.query.filter_by(author_id=current_user.id).all()
    adv_to_delete = None
    if request.method == 'POST':
        adv_id = request.form['id']
        adv_to_delete = Advertisements.query.get(adv_id)
        if adv_to_delete.author_id != current_user.id:
            errors.append("У вас нет прав для удаления данного объявления!")
            return render_template("delete.html", errors = errors, advertisements=advertisements)
        if adv_to_delete:
            db.session.delete(adv_to_delete)
            db.session.commit()

            return redirect(url_for('account'))

    return render_template('delete.html', advertisements=advertisements, errors=errors)


@app.route('/edit_user', methods=['GET', 'POST'])
@login_required
def edit_user():
    user = Users.query.all()
    if request.method == 'POST':
        id_user = request.form['id']
        edit_user = Users.query.get(id_user)
        edit_user.username = request.form['username']
        edit_user.name = request.form['name']
        edit_user.avatar = request.form['avatar']
        edit_user.contact = request.form['contact']
        edit_user.about = request.form['about']
        db.session.commit()
        return redirect(url_for('account'))

    return render_template('edit_users.html', user=user)


@app.route('/delete_user', methods=['GET', 'POST'])
@login_required
def delete_user():
    user = Users.query.all()
    if request.method == 'POST':
        id_user = request.form['id']
        delete = Users.query.get(id_user)
        db.session.delete(delete)
        db.session.commit()
        return redirect(url_for('account'))

    return render_template('delete_users.html', user=user)


@app.route('/delete_adv', methods=['GET', 'POST'])
@login_required
def delete_adv():
    adv = Advertisements.query.all()
    if request.method == 'POST':
        id_adv = request.form['id']
        delete = Advertisements.query.get(id_adv)
        db.session.delete(delete)
        db.session.commit()
        return redirect(url_for('account'))

    return render_template('delete_adv.html', adv=adv)


# Страница выхода из системы
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))