
from flask_app import app
from flask import render_template, redirect, request, session, flash
from flask_app.models.user import User
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/register', methods= ['POST'])
def register():
    if not User.validate_register(request.form):
        return redirect('/')
    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    register_user = {
        "first_name": request.form["first_name"],
        "last_name": request.form["last_name"],
        "email": request.form["email"],
        "password": pw_hash
    }
    user_id = User.save_user(register_user)
    session['user_id'] = user_id
    flash("You have been registerd!")
    return redirect('/result')
    
@app.route('/login', methods= ['POST'])
def login():
    if not User.validate_login(request.form):
        return redirect('/')
    user = User.get_email(request.form)
    if user:
        if not bcrypt.check_password_hash(user.password, request.form["password"]):
            flash("Your Email/Password combination doesn't match")
            return redirect('/')
        session['user_id'] = user.id
        flash("Login was succesful!")
        return redirect ('/result')
    flash("Email not Valid!")
    return redirect('/result')


@app.route('/result')
def results():
    if 'user_id' not in session:
        return redirect('/logout')
    data = {
        "id": session['user_id']
    }
    return render_template('result.html', user = User.get_id(data))


@app.route('/logout')
def logout():
    session.clear()
    return redirect ('/')