import os
from flask import Flask, render_template, redirect, request, session, url_for, flash, render_template_string
from flask_session import Session
from jinja2 import Markup
from cs50 import SQL
from werkzeug.utils import secure_filename
from helper import error, success
from werkzeug.security import check_password_hash, generate_password_hash
from password_strength import PasswordPolicy
from password_strength import PasswordStats
from flask_recaptcha import ReCaptcha # Import ReCaptcha object
from categories import category #Differentiate category
import colorama,termcolor
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from keras.models import load_model
from keras.utils import pad_sequences
import stripe
from datetime import datetime, timedelta
from datetime import datetime as dt
import socket
import pyotp
import alerting
import joblib
import numpy as np

stripe.api_key = 'YOUR API'

# Load the saved model
model = load_model("sql_injection_detection_model3.h5")
max_sequence_length = 5  
# load the encoder and LabelEncoder
tokenizer = joblib.load('tokenizer.pkl')
encoder = joblib.load('encoder.pkl')


colorama.init()


#configure application
app = Flask(__name__)

policy = PasswordPolicy.from_names(
    length=15, # min length 15
    uppercase=1, # Min 1 uppercase
    numbers=1, # min 1 digits
    strength=0.7 # password that scores at least 0.7 entropy is needed
)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

#session
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['SECRET_KEY'] = '!@&#^!%^@&#@!^*#&DHHSB!13'
Session(app)

# Configure CS50 Librarcdy to use SQLite database
db = SQL("sqlite:///elibrary.db")

#Upload Folder path
UPLOAD_FOLDER = 'static/upload'
#allow extensions
ALLOWED_EXTENSIONS = {'png','pdf', 'jpg', 'jpeg', 'gif', 'svg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configure Google Recaptcha keys
app.config['RECAPTCHA_SITE_KEY'] = '6LdPgnQhAAAAABeSZUIFYts9dTRP2N6RiKbtYRpv' 
app.config['RECAPTCHA_SECRET_KEY'] = '6LdPgnQhAAAAAOrrfRxmNmazPAupYBau_N6OXDiH' 
recaptcha = ReCaptcha(app) 


#root directory
@app.route("/")
@limiter.limit("5 per minute")
def index():
    
    ###
    ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    invalidip = checkValidIPv4(ip)
    if invalidip:
        return error(invalidip)
    
    if not session.get("user_id"):
        return redirect("/login")

    ###
    if not session.get("user_id"):
        return redirect("/login")
    
    if not session.get("subscription_id"):
        flash("You do not have active subscription. Please subscribe")
        return redirect("/subscribe")
    
    else:
        subscription_id = session.get("subscription_id")
        if  not dt.strptime(subscription_id,'%Y-%m-%d %H:%M:%S') >= dt.now():
            flash("You subscription has expired. Please subscribe again!.")
            return redirect("/subscribe")
        
    
    #show books from the database
    data = db.execute("SELECT * FROM books")
    #to get the number of books
    count = db.execute("SELECT COUNT(*) FROM books")
    count_num = count[0]["COUNT(*)"]
    #return the book number and books
    return render_template("index.html", data=data, count=count_num)


@app.route('/subscribe', methods=['GET', 'POST'])
def subscribe():
    return render_template('subscribe.html')

@app.route('/payment_successful', methods=['GET','POST'])
def payment_successful():
    userid = session.get("user_id")
    end_date = dt.now() + timedelta(days=30)
    session['subscription_id'] = end_date
    db.execute("UPDATE users set subscription = ? where id = ?",end_date,userid)

    return redirect('/')

def checkValidIPv4(ip):
    try:
        socket.inet_aton(ip)
        return ""
    except socket.error:
        return "Not valid IP. Ip seems to be spoofed."  


#User register
@app.route("/register", methods=["POST","GET"])
@limiter.limit("5 per minute")
def register():

    if request.method == "POST":
        if recaptcha.verify():
        #get user information
            username = request.form.get("username")
            email = request.form.get("email")
            fullname = request.form.get("fullname")
            address = request.form.get("address")
            birth = request.form.get("birth")
            password = request.form.get("password")
            confirm_password = request.form.get("confirm_password")

            stats = PasswordStats(password)
            checkpolicy = policy.test(password)
            if stats.strength() < 0.7:
                print(stats.strength())
                flash("Password not strong enough. Avoid consecutive characters and easily guessed words.")
                return render_template("register.html")
        #check the passwords are match or not
            if password != confirm_password:
                return error("Password do not match!")
            


        #change password to hash
            hash = generate_password_hash(password)

        #insert into database
            create = db.execute("INSERT INTO users (username, email, password, fullname, address, birth) VALUES (?, ?, ?, ?, ?, ?)",username, email, hash, fullname, address, birth)
            if create:
                return redirect(url_for("login_2fa",username = username ))
                #return success("Account created successfully!")
            else:
                return error("Account has already been registered!")
        
        #reCaptcha error message
        else:
            flash(u'Please verify reCaptcha', 'error')
            return render_template("register.html")

    else:
        return render_template("register.html")

# 2FA page route
@app.route("/login/2fa/<string:username>")
@limiter.limit("5 per minute")
def login_2fa(username):
    # generating random secret key for authentication
    username = username
    secret = pyotp.random_base32()
    return render_template("login_2fa.html", secret=secret, username = username)

# 2FA form route
@app.route("/login/2fa/<string:username>",methods=['POST','GET'])
@limiter.limit("5 per minute")
def login_2fa_form(username):
    # getting secret key used by user
    secret = request.form.get("secret")
    # getting username
    username = username
    # getting OTP provided by user
    otp = int(request.form.get("otp"))
    # verifying submitted OTP with PyOTP
    if pyotp.TOTP(secret).verify(otp):
        # inform users if OTP is valid
        flash(u"The TOTP 2FA token is valid")
        db.execute("UPDATE users set OTP = ? where username = ?",secret,username)
        #flash(u'Username or Password is wrong!', 'error')
        #return redirect("/")
        return success("Account created successfully!")
    else:
        # inform users if OTP is invalid
        flash(u"You have supplied an invalid 2FA token!", "error")
        return redirect(url_for("login_2fa"))

#User Login 
@app.route("/login", methods=["POST","GET"])
@limiter.limit("5 per minute")
def login():
    #clear session
    session.clear()
    if request.method == "POST":
        if recaptcha.verify():
            #get user input
            username = request.form.get("username")
            patterntester(str(username))
            password = request.form.get("password")
            otp = request.form.get("otp")
            #check user name
       
            rows = db.execute("SELECT * FROM users WHERE username = ?", username)
            #check password
            if len(rows) != 1 or not check_password_hash(rows[0]["password"], password):
                #return error("Username or Password is wrong!")
                flash(u'Username or Password is wrong!', 'error')
                return render_template("login.html")
            
            #retriving secret from DB and verify OTP
            secret = rows[0]["OTP"]
            if pyotp.TOTP(secret).verify(otp):
                #remember which user has logged in
                session["user_id"] = rows[0]["id"]
                session["subscription_id"] = rows[0]["subscription"]
                #redirect into homepage
                return redirect("/")
            else:
                flash(u'Your OTP is invalid!', 'error')
                return render_template("login.html")

        else:
            flash(u'Please verify reCaptcha', 'error')
            return render_template("login.html")
            
    else:        
        return render_template("login.html")

    
@app.route("/logout")
@limiter.limit("5 per minute")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

#User Account page
@app.route("/account")
@limiter.limit("5 per minute")
def account():
    #check user login or not
    if not session.get("user_id"):
        return redirect("/login")
    
    #get user id
    user = session.get("user_id")
    #get user data from database
    user_info = db.execute("SELECT * FROM users WHERE id = ?", user)
    return render_template("account.html", userInfo = user_info)

# Change Password
@app.route("/change-password", methods=["POST","GET"])
@limiter.limit("5 per minute")
def changePassword():
    if not session.get("user_id"):
        return redirect("/login")

    #Getting current in user info
    user_id = session.get("user_id")
    user_info = db.execute("SELECT * FROM users WHERE id = ?", user_id)
    if request.method == "POST":
        #to get the current password
        current_password = request.form.get("current-password")
        #to get new password
        new_password = request.form.get("new-password")
        confirm_password = request.form.get("confirm-password")

        rows = db.execute("SELECT password FROM users WHERE id = ? ", user_id)
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], current_password):
            return error("Current password is wrong!")

        #check new password
        if new_password != confirm_password:
            return error("Password do not match!")
        else:
            #password policy
            stats = PasswordStats(confirm_password)
            checkpolicy = policy.test(confirm_password)
            if stats.strength() < 0.7:
                print(stats.strength())
                flash("Password not strong enough. Avoid consecutive characters and easily guessed words.")
                return render_template("account.html", userInfo = user_info)
            #Password Hashing
            hash = generate_password_hash(confirm_password)
            change_password = db.execute("UPDATE users SET password = ? WHERE id = ?", hash, user_id)
            if change_password:
                return success("Password changed successfully!")
            else:
                return error("Failed!")
    return render_template("account.html", userInfo = user_info)
    
# Change User Info
@app.route("/change-userinfo", methods=["POST","GET"])
@limiter.limit("5 per minute")
def changeUserInfo():
    #check user session
    if not session.get("user_id"):
        return redirect("/login")
    #get user id
    user_id = session.get("user_id")
    #get user data
    user_info = db.execute("SELECT * FROM users WHERE id = ?", user_id)
    if request.method == "POST":
        #get user data form 
        username = request.form.get("username")
        email = request.form.get("email")
        fullname = request.form.get("fullname")
        birth = request.form.get("birth")
        address = request.form.get("address")
        #update the data
        row = db.execute("UPDATE users SET username =  ?, email = ?, fullname = ?, birth = ?, address = ? WHERE id = ?", username, email, fullname, birth, address, user_id)
        #check update is success or not
        if row:
            return success("Update Successfully!")
        else:
            return error("Failed! Please Try Again!")
    #return the account template with user data
    return render_template("account.html", userInfo = user_info)

#Admin Login
@app.route("/admin-login", methods=["POST","GET"])
@limiter.limit("5 per minute")
def admin():
    #clear session
    session.clear()

    if request.method == "POST":
        if recaptcha.verify():
            #get username, password and otp
            username = request.form.get("username")
            patterntester(str(username))
            password = request.form.get("password")
            otp = request.form.get("otp")

            #SELECT data from table
            rows = db.execute("SELECT * FROM admin WHERE username = ?", username)

            #Checking if the hashes match
            if len(rows) != 1 or not check_password_hash(rows[0]["password"], password):
                flash(u'Username or Password is wrong!', 'error')
                return render_template("admin.html")

            #retriving secret from DB and verify OTP
            secret = rows[0]["OTP"]
            if pyotp.TOTP(secret).verify(otp):
                #remember which admin has logged in
                session["admin_id"] = rows[0]["id"]
                #redirect into dashboard
                return redirect("/dashboard")
            else:
                flash(u'Your OTP is invalid!', 'error')
                return render_template("admin.html")

            #session["admin_id"] = rows[0]["id"]      

        else:
            flash(u'Please verify reCaptcha', 'error')
            return render_template("admin.html")

    else:
        return render_template("admin.html")

#Profile page
@app.route("/profile")
@limiter.limit("5 per minute")
def profile():
    if not session.get("admin_id"):
        return redirect("/admin-login")
    admin_id = session.get("admin_id")
    #show books from the database
    data = db.execute("SELECT * FROM books")
    #to get the number of books
    count = db.execute("SELECT COUNT(*) FROM books")
    count_num = count[0]["COUNT(*)"]

    #get information
    info = db.execute("SELECT * FROM admin WHERE id = ?", admin_id)
    return render_template("profile.html", books=data, count=count_num, info = info)

# Admin Dashbaord
@app.route("/dashboard")
@limiter.limit("5 per minute")
def dashboard():
    if not session.get("admin_id"):
        return redirect("/admin-login")
    
    # Showing all book data
    data = db.execute("SELECT * FROM books")
    count = db.execute("SELECT COUNT(*) FROM books")
    count_num = count[0]["COUNT(*)"]
    return render_template("dashboard.html", books=data, count=count_num)

# Admin Logout
@app.route("/admin-logout")
@limiter.limit("5 per minute")
def admin_logout():
    #forget session
    session.clear()

    #redirect to home page
    return redirect("/")

# Restricting file extension for File Upload Vulnerability
def allowed_file(file_name):
    return '.' in file_name and \
        file_name.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

#Book Upload
@app.route("/upload", methods = ["POST","GET"])
@limiter.limit("5 per minute")
def upload():
    if not session.get("admin_id"):
        return redirect("/admin-login")

    #Taking book infos
    if request.method == "POST":
        book_name = request.form.get("book_name")
        description = request.form.get("description")
        author = request.form.get("author")
        category = request.form.get("categories")
        link = request.form.get("link")

        if "book_image" not in request.files:
            flash("No File Part")
            return redirect(request.url)
        book_image = request.files["book_image"] 

        if book_image.filename == "":
            flash("No selected file")
            return redirect(request.url)
        
        if book_image and allowed_file(book_image.filename):
            book_image_name = secure_filename(book_image.filename)
            book_image.save(os.path.join(app.config["UPLOAD_FOLDER"], book_image_name))
        else:
            return error("Allowed image type are - png, jpg, jpeg, gif, pdf, svg")
        
        # Inserting book into DB
        add_book = db.execute("INSERT INTO books (book_name, description, categories, author, link, image) VALUES (?, ?, ?, ?, ?, ?)", book_name, description, category, author, link, book_image_name)
        if add_book:
            return success("Upload Successfully!")
        else:
            return error("Failed!")
    return render_template("upload.html")

#Book Edit
@app.route("/edit/<id>")
@limiter.limit("5 per minute")
def edit(id):
    if not session.get("admin_id"):
        return redirect("/admin-login")
    #print book data with id
    book_data = db.execute("SELECT * FROM books WHERE id = ?", id)
    #return data for edit
    return render_template("edit.html", id=id, book=book_data)

@app.route("/edit-book", methods=["POST","GET"])
@limiter.limit("5 per minute")
def editBook():
    if not session.get("admin_id"):
        return redirect("/admin-login")
    
    if request.method == "POST":
        #get book data
        id = request.form.get("id")
        book_name = request.form.get("book_name")
        description = request.form.get("description")
        author = request.form.get("author")
        category = request.form.get("categories")
        link = request.form.get("link")

        if "book_image" not in request.files:
            flash("No File Part")
            return redirect(request.url)
        book_image = request.files["book_image"] 

        if book_image.filename == "":
            flash("No selected file")
            return redirect(request.url)
        
        if book_image and allowed_file(book_image.filename):
            book_image_name = secure_filename(book_image.filename)
            book_image.save(os.path.join(app.config["UPLOAD_FOLDER"], book_image_name))
        else:
            return error("Allowed image type are - png, jpg, jpeg, gif, pdf, svg")        
        
        #Updating Book info into Db
        add_book = db.execute("UPDATE books SET book_name = ?, description = ?, categories = ?, author = ?, link = ?, image = ? WHERE id = ?", book_name, description, category, author, link, book_image_name, id)
        if add_book:
            return success("Upload Successfully!")
        else:
            return error("Failed!")


    return redirect("/dashboard")

#Deleting a Book
@app.route("/delete/<id>", methods=["POST","GET"])
@limiter.limit("5 per minute")
def delete(id):
    if not session.get("admin_id"):
        return redirect("/admin-login")
    
    delete = db.execute("DELETE FROM books WHERE id = ?", id)
    
    if delete:
        flash("Deleted!")
    else:
        flash("Failed!")

    return redirect("/dashboard")

#Changing Admin Password
@app.route("/change-pw", methods=["POST","GET"])
@limiter.limit("5 per minute")
def changeAdminPassword():
    if not session.get("admin_id"):
        return redirect("/admin-login")
    admin_id = session.get("admin_id")
    if request.method == "POST":
        #to get the current password
        current_password = request.form.get("current_password")
        #to get new password
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        rows = db.execute("SELECT password FROM admin WHERE id = ? ", admin_id)
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], current_password):
            return error("Current password is wrong!")

        #check new password
        if new_password != confirm_password:
            return error("Password do not match!")
        else:
            #password policy
            stats = PasswordStats(confirm_password)
            checkpolicy = policy.test(confirm_password)
            if stats.strength() < 0.7:
                print(stats.strength())
                flash("Password not strong enough. Avoid consecutive characters and easily guessed words.")
                return render_template("profile.html")
            # Password Hashing
            hash = generate_password_hash(confirm_password)
            change_password = db.execute("UPDATE admin SET password = ? WHERE id = ?", hash, admin_id)
            if change_password:
                return success("Password changed successfully!")
            else:
                return error("Failed!")
    return render_template("profile.html")

#Book Details
@app.route("/details/<id>")
@limiter.limit("5 per minute")
def details(id):
    book_id = id
    data = db.execute("SELECT * FROM books WHERE id = ?", book_id)
    return render_template("details.html", book=data)

@app.route('/search', methods=["GET","POST"])
@limiter.limit("5 per minute")
def search():
    searched = request.form['searched']
    patterntester(str(searched))
    if not session.get("user_id"):
        return redirect("/login")
    #show books from the database
    data = db.execute("SELECT * FROM books WHERE book_name LIKE ? OR categories LIKE ? OR author LIKE ? OR description LIKE ?",'%'+searched+'%','%'+searched+'%','%'+searched+'%','%'+searched+'%')
    #to get the number of books
    count = len(data)
    return render_template("search.html", data=data, count=count)

#Contact page
@app.route('/contact', methods = ["POST","GET"])
@limiter.limit("5 per minute")
def contact():
    if not session.get("user_id"):
        return redirect("/login")
    
    return render_template("contact.html")

# Adding user infos
@app.route("/users")
@limiter.limit("5 per minute")
def users():
    #Check admin is login or not
    if not session.get("admin_id"):
        return redirect("/admin-login")
    
    #get user data from database
    user_infos = db.execute("SELECT * FROM users")
    count = db.execute("SELECT COUNT(*) FROM users")
    count_num = count[0]["COUNT(*)"]

    return render_template("users.html", userInfos = user_infos , count=count_num)
#END


#Pattern matching
def match(pattern, string):
    prevpattern = pattern
    if len(pattern) == len(string) and pattern == string:
            return ((len(pattern)/len(string)) * 100)
    else:
        pattern = pattern.split(" ")
        string = string.split(" ")
        #matched_count = 0
        lenofmatched = 0
        matched = []
        try:
            for i in range(len(string)):
                for j in range(len(pattern)):
                    #if (string[i] == pattern[j]):
                    if(pattern[j] in string[i] and pattern[j] not in matched):
                        matched.append(pattern[j])
                        #matched_count += 1
                        lenofmatched += len(pattern[j])
                 
            return lenofmatched/len(prevpattern) * 100
        except IndexError:
            return lenofmatched/len(prevpattern) * 100

#Pattern Tester
def patterntester(string):
    inputString = string
    print("Input is : "+ inputString)
    knownpatterns = []
    knownpatternsfromDB = []
    counter = 0
    percentage = 0
    threshold = 70
    longest_match_pattern = ""
    longest_match_percentage = 0 
    cate = ""   
    #sqliDict = {}

    data = db.execute("SELECT * FROM knownpatterns")
    for line in data:
        knownpatternsfromDB.append(line['knownpatterns'])

    for line in open('knownpatterns.txt', "r"):
        knownpatterns.append(line.rstrip('\n'))
        
    
    for line in knownpatterns:
        if len(line) != 0:
            #Calling matching function and wait for percentage match
            percentage = match(line, inputString)
            
            if percentage == 100:
                counter += 1
                if len(longest_match_pattern) < len(line) and len(line) == len(inputString):
                    longest_match_pattern = line
                    longest_match_percentage = percentage

                # Preprocess the query
                new_sequence = tokenizer.texts_to_sequences([inputString])
                new_padded = pad_sequences(new_sequence, maxlen=5) 

                # Make prediction
                prediction = model.predict(new_padded)

                # Get the class with the highest probability
                predicted_class = np.argmax(prediction, axis=-1)

                # load the LabelEncoder
                encoder = joblib.load('encoder.pkl')

                # Get the label for the predicted class
                predicted_label = encoder.inverse_transform(predicted_class)
                predicted_category = predicted_label[0]

                #Print Output
                print(f"Pattern is :: {line}")
                print(f"Pattern matched :: {percentage:.2f} %")
                print(f"Injection Type :: {predicted_category}")
                print(termcolor.colored(f"SQL Injection detected!",color='red'))
  
            elif (percentage > threshold):
   
                # Preprocess the query
                new_sequence = tokenizer.texts_to_sequences([inputString])
                new_padded = pad_sequences(new_sequence, maxlen=5) 

                # Make prediction
                prediction = model.predict(new_padded)

                # Get the class with the highest probability
                predicted_class = np.argmax(prediction, axis=-1)

                # Get the label for the predicted class
                predicted_label = encoder.inverse_transform(predicted_class)
                predicted_category = predicted_label[0]
                counter += 1

                #Print Output
                print(f"Pattern is :: {line}")
                print(f"Pattern matched :: {percentage:.2f} %")
                print(f"Injection Type :: {predicted_category}")
                print(termcolor.colored(f"SQL Injection detected!",color='red'))

    ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    if counter > 0:
        print(termcolor.colored(f"Alerting to admin! Attacker's ip address is {ip} and Injection Type is {predicted_category}",color = 'green'))  
        ts = str(dt.now())
        alerting.send_to_sheet(ip,str(inputString),predicted_category,ts)
     
if __name__ == "__main__":
    # Running App with Secure Socket Layer with ECDSA-(secp521bit)-SHA384 encryption
    app.run(ssl_context=('secp521.crt', 'secp521.ec.key'),debug=False)





   
