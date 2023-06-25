from werkzeug.security import generate_password_hash
from cs50 import SQL

db = SQL("sqlite:///elibrary.db")
username = input("username: ")
email = input("email: ")
fullname = input("fullname: ")
address = input("address: ")
birth = input("birth: ")
password = input("password: ")
confirm_password = input("confirm_password: ")
hash = generate_password_hash(password)
if password == confirm_password:
    create = db.execute("INSERT INTO admin (username, email, password, fullname, address, birth) VALUES (?, ?, ?, ?, ?, ?)",username, email, hash, fullname, address, birth)
else:
    print("Passwords do not match")