import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Get username
    user = db.execute("SELECT username, cash FROM users WHERE id = :user_id", user_id = session["user_id"])
    username = user[0]["username"]

    # set some temp
    total_cash_in_stock = 0

    # Delete the stock if the share = 0
    portfolios = db.execute("SELECT Symbol, Shares FROM portfolio WHERE id = :user_id AND Shares = :share", user_id = session["user_id"], share = 0)
    if not portfolios:
        # Get new portfolios from TABLE portfolio
        portfolios = db.execute("SELECT Symbol, Shares, Price_per_share, Time, Total FROM portfolio WHERE id = :user_id", user_id = session["user_id"])

    elif portfolios[0]["Shares"] == 0:
        db.execute("DELETE FROM portfolio WHERE id = :user_id AND Shares = :share", user_id = session["user_id"], share = 0)

        # Renew the portfolios again
        portfolios = db.execute("SELECT Symbol, Shares, Price_per_share, Time, Total FROM portfolio WHERE id = :user_id", user_id = session["user_id"])

    for portfolio in portfolios:
        username = username
        symbol = portfolio["Symbol"]
        shares = portfolio["Shares"]
        stock = lookup(symbol)
        price_per_share = stock["price"]
        total = shares * price_per_share

        total_cash_in_stock += total


    # Get user's cash
    cash_remaining = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id = session["user_id"])
    cash_remaining = cash_remaining[0]["cash"]

    # Calculate user's current total assests
    total_assests = cash_remaining + total_cash_in_stock

    return render_template("portfolio.html", username = username, stocks = portfolios, cash_remaining = usd(cash_remaining), total_assests = usd(total_assests))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))

        # Validify the stock symbol
        if quote == None:
            return apology("invalid symbol", 400)

        # Get username
        username = db.execute("SELECT username FROM users WHERE id = :user_id", user_id = session["user_id"])
        username = username[0]["username"]

        # Check if the share is a positive integer
        try:
            share = int(request.form.get("shares"))
        except:
            return apology("Please enter a positive integer for share", 400)

        # Check if the share is > 0
        if share <= 0:
            return apology("Can't sell 0 or less than 0 shares", 400)

        # Get user id from db
        rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id = session["user_id"])

        # Check how much cash this user has
        cash_remaining = rows[0]["cash"]
        price_per_share = quote["price"]

        total_price = price_per_share * share

        if total_price > cash_remaining:
            return apology("You don't have enough money")

        # Select user data from TABLE portfolio
        portfolio = db.execute("SELECT * FROM portfolio WHERE id = :user_id AND Symbol = :symbol", user_id = session["user_id"], symbol = request.form.get("symbol"))

        # If user does not have this stock, insert it into portfolio
        if not portfolio:
            # Update user's cash
            db.execute("UPDATE users SET cash = cash - :total_price WHERE id = :user_id", total_price = total_price, user_id = session["user_id"])

            # Add this to user's portfolio
            db.execute("INSERT INTO portfolio (id, username, Symbol, Shares, Price_per_share, Time, Total) VALUES(:user_id, :username, :symbol, :share, :price_per_share, :time, :total)",
            user_id = session["user_id"],
            username = username,
            symbol = request.form.get("symbol"),
            share = share,
            price_per_share = price_per_share,
            time = datetime.now().isoformat(timespec='microseconds'),
            total = usd(share * price_per_share),
            )

            flash("You already bought some new stocks!")

        # If the user already has this stock, update the portfolio
        else:
            db.execute("UPDATE users SET cash = cash - :total_price WHERE id = :user_id", total_price = total_price, user_id = session["user_id"])
            current_share = db.execute("SELECT Shares FROM portfolio WHERE id = :user_id AND Symbol = :symbol", user_id = session["user_id"], symbol = request.form.get("symbol"))
            updated_share = current_share[0]["Shares"] + share
            db.execute("UPDATE portfolio SET Shares = :share, Price_per_share = :price_per_share, Total = :total, Time = :time WHERE id = :user_id AND Symbol = :symbol",
            user_id = session["user_id"],
            symbol = request.form.get("symbol"),
            share = updated_share,
            price_per_share = price_per_share,
            time = datetime.now().isoformat(timespec='microseconds'),
            total = share * usd(price_per_share)
            )

            flash("You already bought those stocks!")

        # Book keeping
        db.execute("INSERT into history (id, username, Symbol, Shares, Price_per_share, Time, Action, Total) VALUES(:user_id, :username, :symbol, :share, :price_per_share, :time, :action, :total)",
        user_id = session["user_id"],
        username = username,
        symbol = request.form.get("symbol"),
        share = share,
        price_per_share = usd(price_per_share),
        time = datetime.now().isoformat(timespec='microseconds'),
        action = "Buy",
        total = share * price_per_share
        )

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    return jsonify("TODO")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Get username
    username = db.execute("SELECT username FROM users WHERE id = :user_id", user_id = session["user_id"])
    username = username[0]["username"]

    # Get history from TABLE history
    portfolios = db.execute("SELECT * FROM history WHERE id = :user_id", user_id = session["user_id"])

    # Get user's cash
    cash_remaining = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id = session["user_id"])
    cash_remaining = cash_remaining[0]["cash"]

    for portfolio in portfolios:
        username = username
        symbol = portfolio["Symbol"]
        shares = portfolio["Shares"]
        price_per_share = portfolio["Price_per_share"]
        time = portfolio["Time"]
        action = portfolio["Action"]
        total = portfolio["Total"]


    return render_template("history.html", username = username, stocks = portfolios, cash_remaining = usd(cash_remaining))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        # Password are first hashed and passed to the database, the administration cannot see the password
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))

        # Validify the stock symbol
        if quote == None:
            return apology("invalid symbol", 400)

        return render_template("quoted.html", quote = quote)

    # If users reach here through GET
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Confirm password
        elif not request.form.get("password") == request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        # Insert username and password
        # Password are first hashed and passed to the database, the administration cannot see the password
        # Instead, the administration see hashed password, which is writen at the column 2 of Table users, Database finance.db
        hash = generate_password_hash(request.form.get("password"))
        new_user_id = db.execute("INSERT INTO users(username, hash) VALUES(:username, :hash)", username=request.form.get("username"), hash=hash)

        # Check if the username is taken
        if not new_user_id:
            return apology("This username is already taken", 400)

        # Remember which user has logged in
        session["user_id"] = new_user_id

        # Display a flash message
        flash("You are successfully registered")

        # Redict to index.html
        return render_template("success.html")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))

        # Validify the stock symbol
        if quote == None:
            return apology("invalid symbol", 400)

        # Get username
        username = db.execute("SELECT username FROM users WHERE id = :user_id", user_id = session["user_id"])
        username = username[0]["username"]

        # Check if the share is a positive integer
        try:
            share = int(request.form.get("shares"))
        except:
            return apology("Please enter a positive integer for share", 400)

        # Check if the share is > 0
        if share <= 0:
            return apology("Can't sell 0 or less than 0 shares", 400)

        # Get user id from db
        rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id = session["user_id"])

        # Check how much cash this user has
        cash_remaining = rows[0]["cash"]
        price_per_share = quote["price"]

        total_price = price_per_share * share

        # Select user data from TABLE portfolio
        portfolio = db.execute("SELECT * FROM portfolio WHERE id = :user_id AND Symbol = :symbol", user_id = session["user_id"], symbol = request.form.get("symbol"))
        # If user does not have this stock, return apology
        if not portfolio:
            return apology("You don't have this stock", 400)

        elif share > portfolio[0]["Shares"]:
            return apology("You don't have enough shares", 400)

        # If the user already has this stock, update the portfolio
        else:
            # Update user's cash
            db.execute("UPDATE users SET cash = cash + :total_price WHERE id = :user_id", total_price = total_price, user_id = session["user_id"])
            current_share = db.execute("SELECT Shares FROM portfolio WHERE id = :user_id AND Symbol = :symbol", user_id = session["user_id"], symbol = request.form.get("symbol"))
            updated_share = current_share[0]["Shares"] - share
            db.execute("UPDATE portfolio SET Shares = :share, Price_per_share = :price_per_share, Total = :total, Time = :time WHERE id = :user_id AND Symbol = :symbol",
            user_id = session["user_id"],
            symbol = request.form.get("symbol"),
            share = updated_share,
            price_per_share = price_per_share,
            time = datetime.now().isoformat(timespec='microseconds'),
            total = usd(share * price_per_share)
            )

            flash("You already sold those stocks!")

        # Book keeping
        db.execute("INSERT into history (id, username, Symbol, Shares, Price_per_share, Time, Action, Total) VALUES(:user_id, :username, :symbol, :share, :price_per_share, :time, :action, :total)",
        user_id = session["user_id"],
        username = username,
        symbol = request.form.get("symbol"),
        share = share,
        price_per_share = price_per_share,
        time = datetime.now().isoformat(timespec='microseconds'),
        action = "Sell",
        total = share * usd(price_per_share)
        )

        return redirect("/")

    else:
        return render_template("sell.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
