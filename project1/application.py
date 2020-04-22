# goodreads api key: ia0y3Zog4AMrxPVUX0uQ
import os
import requests
import json

from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required


app = Flask(__name__)

# Check for environment variable
if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set")

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set up database
engine = create_engine(os.getenv("DATABASE_URL"))
db = scoped_session(sessionmaker(bind=engine))

@app.route("/")
def index():
    return render_template("about.html")


@app.route("/searchpage")
@login_required
def searchpage():
    return render_template("search.html")

@app.route("/search", methods=["GET"])
@login_required
def search():
    if not request.args.get("bookQuery"):
        return render_template("error.html", message="Please provide a query to search for!")


    book = "%" + request.args.get("bookQuery") + "%"
    book = book.title()

    bookSearch = db.execute("SELECT isbn, title, author, year FROM books WHERE isbn LIKE :book OR title LIKE :book OR author LIKE :book LIMIT 100", {"book": book})

    if bookSearch.rowcount == 0:
        return render_template("error.html", message="No books matched your query!")

    results = bookSearch.fetchall()
    justTheSearchQuery = request.args.get("bookQuery")
    return render_template("results.html", results=results, justTheSearchQuery=justTheSearchQuery)

@app.route("/book/<isbn>", methods=["GET", "POST"])
@login_required
def bookQuery(isbn):
    if request.method == "POST":
        user = session["user_id"]
        rating = request.form.get("rating")
        rating = int(rating)
        comment = request.form.get("comment")

        # Find out which book is being reviewed
        findBook = db.execute("SELECT * FROM books WHERE isbn = :isbn", {"isbn": isbn})
        book = findBook.fetchone()
        book = book[0]

        # Check for multiple Reviews
        checkUserReviews = db.execute("SELECT * FROM reviews WHERE user_id = :user_id AND book_id = :book_id", {"user_id": user, "book_id": book})

        if checkUserReviews.rowcount == 1:
            return render_template("error.html", message="You have already submitted a review for this book!")

        db.execute("INSERT INTO reviews (user_id, book_id, comment, rating) VALUES (:user_id, :book_id, :comment, :rating)", {"user_id": user, "book_id": book, "comment": comment, "rating": rating})
        db.commit()

        flash("Review Submitted!", "info")

        return redirect("/book/" + isbn)

    else:
        bookInfo = db.execute("SELECT isbn, author, year, title FROM books WHERE isbn = :isbn", {"isbn": isbn}).fetchall()
        apiKey = "ia0y3Zog4AMrxPVUX0uQ"

        apiQuery = requests.get("https://www.goodreads.com/book/review_counts.json", params={"key": apiKey, "isbns": isbn})
        response = apiQuery.json()

        response = response["books"][0]
        bookInfo.append(response)

        # Get User Review Information
        findBook = db.execute("SELECT * FROM books WHERE isbn = :isbn", {"isbn": isbn})
        book = findBook.fetchone()
        book = book[0]

        results = db.execute("SELECT users.username, comment, rating, to_char(time, 'DD Mon YY - HH24:MI:SS') as time FROM users INNER JOIN reviews ON users.id = reviews.user_id WHERE book_id = :book ORDER BY time", {"book": book})
        reviews = results.fetchall()

        return render_template("book.html", bookInfo=bookInfo, reviews=reviews)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not request.form.get("username"):
            return render_template("error.html", message="Please enter your username!")
        elif not request.form.get("password"):
            return render_template("error.html", message="Please enter your password!")

        checkUser = db.execute("SELECT * FROM users WHERE username = :username", {"username": request.form.get("username")})
        resultUser = checkUser.fetchone()

        if resultUser == None:
            return render_template("error.html", message="Invalid Username!")
        elif not check_password_hash(resultUser[2], request.form.get("password")):
            return render_template("error.html", message="Invalid Password!")

        session["user_id"] = resultUser[0]
        session["user_name"] = resultUser[1]

        return redirect("/searchpage")

    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    '''Register a user'''
    # Forget any previous user_id:
    session.clear()

    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("error.html", message="Please enter a username!")

        # Query database for username
        duplicateUser = db.execute("SELECT * FROM users WHERE username = :username",
                          {"username":request.form.get("username")}).fetchone()

        # Check if username already exist
        if duplicateUser:
            return render_template("error.html", message="Username Already Exists!")

        elif not request.form.get("password"):
            return render_template("error.html", message="Password Required!")

        elif not request.form.get("confirmation"):
            return render_template("error.html", message="Password Confirmation Required!")

        elif not request.form.get("password") == request.form.get("confirmation"):
            return render_template("error.html", message="Passwords don't match!")

        passwordHash = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)

        # Insert register into DB
        db.execute("INSERT INTO users (username, password) VALUES (:username, :password)",
                            {"username":request.form.get("username"),
                             "password":passwordHash})

        # Commit changes to database
        db.commit()

        return redirect("/login")

    else:
        return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")
