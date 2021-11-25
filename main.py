from flask import Flask, render_template, flash, redirect, url_for, session, request
from flask_mysqldb import MySQL
from wtforms import Form, StringField, PasswordField, validators, HiddenField
from passlib.hash import sha256_crypt
from functools import wraps
from cryptography.fernet import Fernet

# globals for Fernet encryption
key = b'gsEUSe2ru0R03Y2tBRyOFqjKIUG1fHNQwMAqaVrg294='
cipher_suite = Fernet(key)

# User register form
class RegisterForm(Form):
    username = StringField("Username: ", validators=[validators.Length(min=4, max=25), validators
                           .DataRequired("Please enter a valid username")])
    password = PasswordField("Password: ", validators=[validators
                             .DataRequired("Please enter a valid password"), validators
                             .EqualTo(fieldname="confirm", message="Password doesn't match")])
    confirm = PasswordField("Confirm your password")
# user login form
class LoginForm(Form):
    username = StringField("Username:")
    password = PasswordField("password:")
    id = HiddenField()

###### MYSQL Server Settings
app = Flask(__name__)
app.secret_key = "murat"
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = ""
app.config["MYSQL_DB"] = "Passwords"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"
mysql = MySQL(app)
# empty list to store id of current session (used while writing new data to password table (making inner join with this id)
session_id = []


@app.route("/")
def index():
    return render_template("index.html")


# Detailed data page
@app.route("/page/<string:locid>")
def detail(locid):
    cursor = mysql.connection.cursor()
    query = "SELECT * FROM password WHERE locid = %s"
    result = cursor.execute(query, (locid,))
    if result > 0:
        my_data = cursor.fetchone()
        raw_pw = my_data["user_pw"]
        user_pw = cipher_suite.decrypt(raw_pw).decode()
        ############Danger ZONE!!!######################
        ############With a Print command here password can be stolen################
        return render_template("page.html", my_data=my_data, user_pw=user_pw)
    else:
        return render_template("page.html")


# user login decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" in session:
            return f(*args, **kwargs)
        else:
            flash("You are not authorized to see this page", "danger")
            return redirect(url_for("login"))
    return decorated_function


# this page shows all data that belong to one user
@app.route("/mypage", methods=["GET", "POST"])
@login_required
def mypage():
    cursor = mysql.connection.cursor()
    query = "SELECT locid,title,user_url, user_pw, url FROM password INNER JOIN users ON users.id = password.id WHERE username = %s"
    result = cursor.execute(query, (session["username"],))

    if result > 0:
        my_data = cursor.fetchall()
        return render_template("mypage.html", my_data=my_data)
    else:
        return render_template("mypage.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)
    if request.method == "POST":
        username = form.username.data
        password_entered = form.password.data
        try:
            cursor = mysql.connection.cursor()
            query = "SELECT id, username, password,status FROM users WHERE username = %s"
            result = cursor.execute(query, (username, ))
        except Exception as e:
            print(e)
        if (result) > 0:
            data = cursor.fetchone()
            raw_password = data["password"]
            name = data["username"]
            status = data["status"]
            id_current = data["id"]
            if sha256_crypt.verify(password_entered, raw_password) and status == 1:
                flash("Welcome to Password manager {}".format(name), "success")
                session["logged_in"] = True
                session_id.append(id_current)
                session["username"] = username
                return redirect(url_for("mypage"))
            elif status == 0 and sha256_crypt.verify(password_entered, raw_password):
                flash("Couldn't find user", "danger")
                return redirect(url_for("login"))
            else:
                flash("Wrong password entry", "danger")
                return redirect(url_for("login"))
        else:
            flash("Couldn't find user", "danger")
            return redirect(url_for("login"))
    return render_template("login.html", form=form)


#Register
@app.route("/register",methods = ["GET", "POST"])
def register():
    form = RegisterForm(request.form)

    if request.method == "POST" and form.validate():
        status = 1
        username = form.username.data
        password = sha256_crypt.encrypt(form.password.data)
        cursor = mysql.connection.cursor()
        query = "Insert into users(username,password,status) VALUES(%s,%s,%s)"
        cursor.execute(query, (username, password, status))
        mysql.connection.commit()
        cursor.close()
        flash("User successfully registered", "success")
        return redirect(url_for("login"))
    else:
        return render_template("register.html", form=form)
#Logout
@app.route("/logout")
def logout():
    session_id.clear()
    session.clear()
    return redirect(url_for("login"))


@app.route("/delete/<string:locid>")
@login_required
def delete(locid):
    cursor = mysql.connection.cursor()
    query = "SELECT * FROM password  INNER JOIN users ON users.id = password.id WHERE users.username = %s and password.locid = %s"
    result = cursor.execute(query, (session["username"], locid))
    try:
        if result > 0:
            query_2 = "DELETE from password WHERE locid = %s"
            cursor.execute(query_2, (locid,))
            mysql.connection.commit()
            return redirect(url_for("mypage"))
        else:
            flash("Either no such entry or you are not authorized", "danger")
            return redirect(url_for("index"))
    except Exception as e:
        print(e)


@app.route("/user_delete/<username>",methods=["GET", "POST"])
@login_required
def delete_user(username):
    username = session["username"]
    cursor = mysql.connection.cursor()

    query = "SELECT * FROM users WHERE username = %s "
    result = cursor.execute(query, (username,))
    if result == 0:
        flash("Unauthorized attempt", "danger")
        return redirect(url_for("login"))
    else:
        query_2 = "UPDATE users SET status = 0 WHERE username = %s"
        cursor.execute(query_2, (username,))
        mysql.connection.commit()
        session_id.clear()
        session.clear()
        flash("User deleted. Contact admin if that was not intentional", "danger")
        return redirect(url_for("index"))


@app.route("/edit/<string:locid>", methods=["GET", "POST"])
@login_required
def update(locid):
    if request.method == "GET":
        cursor = mysql.connection.cursor()
        query = "SELECT * FROM password  INNER JOIN users ON users.id = password.id WHERE users.username = %s and password.locid = %s"
        result = cursor.execute(query, (session["username"], locid))
        if result == 0:
            flash("Either no such entry or you are not authorized", "danger")
            return redirect(url_for("index"))
        else:
            current_data = cursor.fetchone()
            form = DataPage()
            form.title.data = current_data["title"]
            form.user_name.data = current_data["user_url"]
            raw_pw = current_data["user_pw"]
            user_pw = cipher_suite.decrypt(raw_pw).decode()
            form.user_pw.data = user_pw
            form.site_url.data = current_data["url"]
            return render_template("update.html", form=form)

    else:
        ## POST request
        form = DataPage(request.form)
        newTitle = form.title.data
        newUsername = form.user_name.data
        pw1 = form.user_pw.data
        pw2 = pw1.encode()
        newPw = cipher_suite.encrypt(pw2)
        newUrl = form.site_url.data

        query_2 = "UPDATE password INNER JOIN users ON password.id=users.id SET password.title = %s,password.user_url=%s,password.user_pw=%s,password.url=%s WHERE locid=%s"
        cursor = mysql.connection.cursor()
        cursor.execute(query_2, (newTitle, newUsername, newPw, newUrl, locid))
        mysql.connection.commit()
        flash("Successfully updated", "success")
        return redirect(url_for("mypage"))


@app.route("/add_data", methods=["GET", "POST"])
def add_data():
    form = DataPage(request.form)
    if request.method == "POST" and form.validate():
        title = form.title.data
        user_name = form.user_name.data
        user_pw_raw = form.user_pw.data
        user_pw_raw_1 = user_pw_raw.encode()
        user_pw = cipher_suite.encrypt(user_pw_raw_1)
        site_url = form.site_url.data
        try:
            cursor = mysql.connection.cursor()
            query = "INSERT INTO password(title, user_url, user_pw, url, id) VALUES(%s,%s,%s,%s,%s)"
            cursor.execute(query, (title, user_name, user_pw, site_url, session_id))
            mysql.connection.commit()
            cursor.close()
            flash("Data successfully added", "success")
            return redirect(url_for("mypage"))
        except Exception as e:
            print(e)
    return render_template("add_data.html", form=form)


class DataPage(Form):
    title = StringField("Title:",validators=[validators.Length(max=50)])
    user_name = StringField("Username:", validators=[validators.Length(max=50)])
    user_pw = StringField("Password:", validators=[validators.Length(max=50)])
    site_url = StringField("Site")


if __name__ == "__main__":
    app.run(host='192.168.1.8')

