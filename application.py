import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

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
    
    # store id of current user
    id = session["user_id"]

    i = 0
    shares = db.execute("SELECT symbol, SUM(number) FROM purchase WHERE id = :id GROUP BY symbol", id=id)
    # make sure that stock which are 0 are not displayed
    while i < len(shares):
        if shares[i]["SUM(number)"] == 0:
            del shares[i]
        else:
            i += 1
    # in which all info about stocks will be stored
    rows = []
    total = 0
    i = 0
    
    # save all of the info of stock in rows line by line in dictionary
    for i in range(len(shares)):
        symbol = lookup(shares[i]["symbol"])
        rows.append(symbol)
        rows[i]["shares"] = shares[i]["SUM(number)"]
        rows[i]["total"] = shares[i]["SUM(number)"]*symbol["price"]
        total += rows[i]["total"]
        # convert both of price and total to usd format
        rows[i]["total"] = usd(rows[i]["total"])
        rows[i]["price"] = usd(rows[i]["price"])
    
    # get cash of the user and add it to total
    cash = db.execute("SELECT cash FROM users WHERE id = :id", id=id)
    cash = cash[0]["cash"]
    total += cash
    
    # return template "index.html" by supplying usd format of cash and total
    return render_template("index.html", rows=rows, cash=usd(cash), total=usd(total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    
    # if post method then get the filled form and give user the stocks
    # else if egt method then show em the form in the first place
    if request.method == "POST":
        # if no symbol or number of stocks render apology
        if not request.form.get("symbol"):
            return apology("Missing Symbol")
        if not request.form.get("shares"):
            return apology("Plz tell How many Shares you want...")
        
        try:
            num_shares = int(request.form.get("shares"))
        except ValueError:
            return apology("Shares must be a Positive Number")
        symbol = request.form.get("symbol")
        share = lookup(symbol)
        # return apology if num_shares not a positive integer
        if num_shares < 1:
            return apology("Shares must be a Positive Number")
        
        # return apology if share does not exist
        if not share:
            return apology("Invalid Symbol")
        
        row = db.execute("SELECT cash FROM users WHERE id = :userid", userid=session["user_id"])
        cash = row[0]["cash"]
        cart_value = num_shares*share["price"]
        
        # apologize if user does not have enough money to buy shares
        if cash < cart_value:
            return apology("Balance Insufficient to complete transaction")
        
        # update the cash to new value after purchase
        db.execute("UPDATE users SET cash = cash - :c WHERE id = :id", c=cart_value, id=session["user_id"])
        # update the use information history of purchase
        db.execute("INSERT INTO purchase(id, name, symbol, price, number) VALUES(:id, :name, :symbol, :price, :number)",
                   id=session["user_id"], name=share["name"], symbol=share["symbol"], price=share["price"], number=num_shares)
        
        # flash message bought stocks
        flash("Stocks Bought:)")
        
        # redirect user to home page
        return redirect("/")
    else:
        # extract symbol_buy from index.html if supplied
        if not request.args.get("symbol_buy"):
            symbol_buy = ""
        else:
            symbol_buy = "value = " + request.args.get("symbol_buy")
        return render_template("buy.html", value=symbol_buy)


@app.route("/add_cash", methods=["GET", "POST"])
@login_required
def add_cash():
    """ADDS cash to user knowing the secret"""
    
    # if method is post adds cash else show the form
    if request.method == "POST":
        
        # if no amount or cheat supplied show form again and flash a message
        if not request.form.get("cash") or not request.form.get("cheat"):
            flash("Enter amount and Cheat Code")
            return redirect("/add_cash")
        
        # validate a positive number is supplied
        try:
            cash = int(request.form.get("cash"))
        except ValueError:
            return apology("Cash must be a +ve integer")
        
        if cash <= 0:
            return apology("Cash must be a +ve integer")
        
        cheat = "This is CS50!!"
        
        if not cheat == request.form.get("cheat"):
            return apology("Wrong Cheatcode:(")
        
        # update the cash
        db.execute("UPDATE users SET cash = cash + :cash WHERE id = :id", cash=cash, id=session["user_id"])
        
        # flash message and redirect to home
        flash("Cheat Code Applied Succesfully:)")
        return redirect("/")

    else:
        return render_template("add_cash.html")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change the password"""
    
    # if method is post change passcode else show the form
    if request.method == "POST":
        
        # apologize if no password
        if not request.form.get("password"):
            return apology("Old Password Required")
        
        # apologize if no password_new or confirmation password
        if not request.form.get("password_new") or not request.form.get("confirmation"):
            return apology("Enter New password")
        
        password = db.execute("SELECT hash FROM users WHERE id = :id", id=session["user_id"])
        
        # validate if user is owner of account or just somehow got accounts access
        if not len(password) == 1 or not check_password_hash(password[0]["hash"], request.form.get("password")):
            return apology("Invalid Password", 403)
        
        # check if 2 password are typed equal
        if not request.form.get("password_new") == request.form.get("confirmation"):
            return apology("Passwords do not match", 403)
        
        # hash the new password and update it
        pwd = generate_password_hash(request.form.get("password_new"), method='pbkdf2:sha256', salt_length=8)
        db.execute("UPDATE users SET hash = :pwd WHERE id = :id", id=session["user_id"], pwd=pwd)
        
        # flash message password changed
        flash("Password Changed Successfully!!")
        
        # redirect to homepage
        return redirect("/")
        
    else:
        return render_template("change_password.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    
    rows = db.execute("SELECT name, symbol, price, number, time FROM purchase WHERE id = :id", id=session["user_id"])
    i = 0
    # adds action and total to rows
    while i < len(rows):
        
        if rows[i]["number"] < 0:
            # makes number positive
            rows[i]["number"] = -rows[i]["number"]
            rows[i]["action"] = "Sold"
        else:
            rows[i]["action"] = "Bought"
        
        rows[i]["price"] = float(rows[i]["price"])
        rows[i]["total"] = float(rows[i]["price"]*rows[i]["number"])
        i += 1
    
    return render_template("history.html", rows=rows)


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
    
    # Displays info if user wants to submit
    if request.method == "POST":
        
        # apologizes if symbols wasnt supplied
        if not request.form.get("symbol"):
            return apology("Missing Symbol", 400)
        
        # apologizes if symbol isn't valid
        share = lookup(request.form.get("symbol"))
        if not share:
            return apology("Invalid Symbol", 400)
        
        # returns info about the symbol asked for
        return render_template("quoted.html", company_name=share["name"], symbol=share["symbol"], cost=usd(share["price"]))
        
   # if request was get then displays the user form for getting quote 
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    
    # Forget any user id
    session.clear()
    
    if request.method == "POST":
        # Checks if valid username
        if not request.form.get("username"):
            return apology("Must Provide Username", 400)
        # checks if valid password
        elif not request.form.get("password") or not request.form.get("confirmation"):
            return apology("Must Provide Password", 400)
        # Checks if passwords match
        elif not request.form.get("password") == request.form.get("confirmation"):
            return apology("Passwords do not match", 400)
        else:
            # hashes the password
            password = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
            result = db.execute("INSERT INTO users(username, hash) VALUES (:u, :p)", u=request.form.get("username"), p=password)
            
            # checks if username already exists or not
            if not result:
                return apology("Username already Exists", 400)
            else:
                rows = db.execute("SELECT id FROM users WHERE username = :u ", u=request.form.get("username"))
                
                # remember which user has logged in
                session["user_id"] = rows[0]["id"]
                # flash registered
                flash("User Registered...")

                # redirect to home page
                return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    
    # if post request then sell the stock
    # else if get request then show the form in first place
    if request.method == "POST":

        # apologize if no symbol or no. of shares
        if not request.form.get("symbol"):
            return apology("Missing Symbol")
        if not request.form.get("shares"):
            return apology("Plz tell how many Shares to Sell")
        
        symbols = db.execute(
            "SELECT symbol, SUM(number) AS number FROM purchase WHERE id = :id GROUP BY symbol", id=session["user_id"])
        i, num_stock = 0, 0
        symbol = request.form.get("symbol")
        share_sell = int(request.form.get("shares"))
        
        # checks if user owns that stock
        while i < len(symbols):
            if symbol == symbols[i]["symbol"]:
                num_stock = int(symbols[i]["number"])
                break
            i += 1
        
        # apologizes if user doesn't own or doesn't have enough stock
        if i == len(symbols):
            return apology("You don't own that Stock")
        if share_sell > num_stock:
            return apology("You don't own that much Stocks")
        
        stock = lookup(symbol)
        # update the users and purchase database
        db.execute("INSERT INTO purchase(id, name, symbol, price, number) VALUES(:id, :name, :symbol, :price, :number)",
                   id=session["user_id"], name=stock["name"], symbol=symbol, price=stock["price"], number=(-share_sell))
        db.execute("UPDATE users SET cash = cash + :amount WHERE id = :id",
                   amount=(share_sell*stock["price"]), id=session["user_id"])
        # flash a message Sold
        flash("Sold!!!")
        # redirect user to home page
        return redirect("/")
        
    else:
        symbols = db.execute(
            "SELECT symbol, SUM(number) AS number FROM purchase WHERE id = :id GROUP BY symbol", id=session["user_id"])
        i = 0
        # just makes sure that stocks who now are 0 due to selling doesn't appear in menu 
        while i < len(symbols):
            if symbols[i]["number"] == 0:
                del symbols[i]
            else:
                i += 1
        
        # get any variable if supplied by get
        # if supplied then have it as default argument else carry on as usual
        if not request.args.get("symbol_sell"):
            html = 'value = "" disabled selected hidden'
            name = "Symbol"
        else:
            name = request.args.get("symbol_sell")
            html = 'value = ' + name + ' selected'
            i = 0
            # just makes sure that stock which was sent as selected doesn't appear twice in menu 
            while i < len(symbols):
                if symbols[i]["symbol"] == name:
                    del symbols[i]
                else:
                    i += 1
        
        return render_template("sell.html", symbols=symbols, html=html, name=name)


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
