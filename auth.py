import functools
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from flaskr.db import get_db
bp = Blueprint('auth', __name__, url_prefix='/auth')
@bp.route('/register', methods=('GET', 'POST'))

def register():
    if request.method == 'POST':
        name = request.form['name']
        mobile_no = request.form['mobile_no']
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        if not name:
            error = 'Name is required.'
        elif not mobile_no:
            error = 'Mobile Number is required.'
        elif not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (name,mobile_no,username, password) VALUES (?,?,?,?)",
                    (name,mobile_no,username, generate_password_hash(password)),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User with {username} is already registered."
            else:
                return redirect(url_for("auth.login"))
        flash(error)
    return render_template('auth/register.html')

@bp.route('/adminregister', methods=('GET', 'POST'))
def adminregister():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO admin_1 (username, password) VALUES (?,?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except db.IntegrityError:
                error = f"Admin {username} is already registered."
            else:
                return redirect(url_for("auth.adminlogin"))
        flash(error)
    return render_template('auth/adminregister.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('auth.userhome'))

        flash(error)

    return render_template('auth/login.html')
@bp.route('/adminlogin', methods=('GET', 'POST'))
def adminlogin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        admin_1 = db.execute(
            'SELECT * FROM admin_1 WHERE username = ?', (username,)
        ).fetchone()

        if admin_1 is None:
            error = 'Incorrect username.'
        elif not check_password_hash(admin_1['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['admin_1_id'] = admin_1['id']
            return redirect(url_for('auth.adminhome'))

        flash(error)

    return render_template('auth/adminlogin.html')


@bp.route('/userhome', methods=('GET', 'POST'))
def userhome():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('auth.userhome'))

        flash(error)

    return render_template('auth/userhome.html')


@bp.route('/adminhome', methods=('GET', 'POST'))
def adminhome():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        admin_1 = db.execute(
            'SELECT * FROM admin_1 WHERE username = ?', (username,)
        ).fetchone()

        if admin_1 is None:
            error = 'Incorrect username.'
        elif not check_password_hash(admin_1['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['admin_1_id'] = admin_1['id']
            return redirect(url_for('auth.adminhome'))

        flash(error)

    return render_template('auth/adminhome.html')

@bp.route('/addservice', methods=('GET', 'POST'))
def addservice():
    if request.method == 'POST':
        service_id = request.form['service_id']
        service_name = request.form['service_name']
        price = request.form['price']
        db = get_db()
        error = None

        if not service_id:
            error = 'Service ID is required.'
        elif not service_name:
            error = 'Service Name is required'
        elif not price:
            error = 'At-least add zero'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO services (service_id,service_name,price) VALUES (?, ?, ?)",
                    (service_id, service_name, price),
                )
                db.commit()
            except db.IntegrityError:
                error = f"Service ID {service_id} is already assigned."
            else:
                return redirect(url_for('auth.adminhome'))
        flash(error)
    return render_template('auth/addservice.html')

@bp.route('/addplaces', methods=('GET', 'POST'))
def addplaces():
    if request.method == 'POST':
        location = request.form['location']
        db = get_db()
        error = None
        if not location:
            error = "Please enter a location"
        if error is None:
            try:
                db.execute(
                    "INSERT INTO places (location) VALUES (?)",
                    (location,),
                )
                db.commit()
            except db.IntegrityError:
                error = "Location already exists."
            else:
                return redirect(url_for('auth.adminhome'))
        flash(error)
    return render_template('auth/addplaces.html')

# @bp.route('/bookservice', methods=('GET', 'POST'))
# def bookservice():
#     locations = db.execute(
#         "SELECT (location) from places",
#         [location]
#     ).fetchall()
#     error = None
#     if method == 'POST':
#         cities = request.form['location']
#         service_name = request.form['service_name']
#         price = request.form['price']
#     if cities not in locations:
#         error = "Sorry we don't serve in your location"
#     if error is None:
#         db.execute(
#             "INSERT INTO ()"
#         )

@bp.route('/viewbookings', methods=('GET', 'POST'))
def viewbookings():
    db = get_db()
    bookings = db.execute(
        "SELECT location FROM places",
    ).fetchone()
    cities = []
    for i in bookings:
        cities.append(i)
    return cities

@bp.before_app_request
def load_logged_in_admin():
    admin_1_id = session.get('admin_1_id')

    if admin_1_id is None:
        g.admin_1 = None
    else:
        g.admin_1 = get_db().execute(
            'SELECT * FROM admin_1 WHERE id = ?', (admin_1_id,)
        ).fetchone()

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return render_template('base.html')