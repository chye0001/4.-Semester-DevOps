import os
import sys
import sqlite3
import hashlib
from datetime import datetime
from contextlib import closing

from flask import Flask, request, session, url_for, redirect, render_template, g, flash, jsonify

################################################################################
# Configuration
################################################################################

DATABASE_PATH = '../whoknows.db'
PER_PAGE = 30
DEBUG = True  # Set to True for development
SECRET_KEY = 'development key'  # Change this in production

app = Flask(__name__)
app.secret_key = SECRET_KEY


################################################################################
# Database Functions
################################################################################

def connect_db(init_mode=False):
    """Returns a new connection to the database."""
    if not init_mode:
        check_db_exists()
    return sqlite3.connect(DATABASE_PATH)


def check_db_exists():
    """Checks if the database exists."""
    if not os.path.exists(DATABASE_PATH):
        print("Database not found", file=sys.stderr)  # Print to stderr for errors
        sys.exit(1)


def init_db():
    """Creates the database tables."""
    with closing(connect_db(init_mode=True)) as db:
        with app.open_resource('../schema.sql') as f:
            db.cursor().executescript(f.read().decode('utf-8'))
        db.commit()
    print(f"Initialized the database: {DATABASE_PATH}")


def query_db(query, args=(), one=False):
    """Queries the database and returns a list of dictionaries."""
    cur = g.db.execute(query, args)
    rv = [dict((cur.description[idx][0], value)
               for idx, value in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv


def get_user_id(username):
    """Convenience method to look up the id for a username."""
    rv = g.db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone() # Use parameterized query
    return rv[0] if rv else None


################################################################################
# Request Handlers
################################################################################

@app.before_request
def before_request():
    """Connect to the database and look up the current user."""
    g.db = connect_db()
    g.user = None
    if 'user_id' in session:
        g.user = query_db("SELECT * FROM users WHERE id = ?", (session['user_id'],), one=True) # Use parameterized query


@app.after_request
def after_request(response):
    """Closes the database connection."""
    if hasattr(g, 'db'): # Check if g.db exists before closing it
        g.db.close()
    return response


################################################################################
# Page Routes
################################################################################

@app.route('/')
def search():
    """Shows the search page."""
    q = request.args.get('q')
    language = request.args.get('language', "en")
    search_results = query_db("SELECT * FROM pages WHERE language = ? AND content LIKE ?", (language, f"%{q}%")) if q else []  # Use parameterized query and f-string
    return render_template('search.html', search_results=search_results, query=q)


@app.route('/about')
def about():
    """Displays the about page."""
    return render_template('about.html')


@app.route('/login')
def login():
    """Displays the login page."""
    if g.user:
        return redirect(url_for('search'))
    return render_template('login.html')


@app.route('/register')
def register():
    """Displays the registration page."""
    if g.user:
        return redirect(url_for('search'))
    return render_template('register.html')



################################################################################
# API Routes
################################################################################

@app.route('/api/search')
def api_search():
    """API endpoint for search. Returns search results."""
    q = request.args.get('q')
    language = request.args.get('language', "en")
    search_results = query_db("SELECT * FROM pages WHERE language = ? AND content LIKE ?", (language, f"%{q}%")) if q else []  # Use parameterized query and f-string
    return jsonify(search_results=search_results)


@app.route('/api/login', methods=['POST'])
def api_login():
    """Logs the user in."""
    error = None
    user = query_db("SELECT * FROM users WHERE username = ?", (request.form['username'],), one=True)  # Use parameterized query
    if user is None:
        error = 'Invalid username'
    elif not verify_password(user['password'], request.form['password']):
        error = 'Invalid password'
    else:
        flash('You were logged in')
        session['user_id'] = user['id']
        return redirect(url_for('search'))
    return render_template('login.html', error=error)


@app.route('/api/register', methods=['POST'])
def api_register():
    """Registers the user."""
    if g.user:
        return redirect(url_for('search'))
    error = None
    if not request.form['username']:
        error = 'You have to enter a username'
    elif not request.form['email'] or '@' not in request.form['email']:
        error = 'You have to enter a valid email address'
    elif not request.form['password']:
        error = 'You have to enter a password'
    elif request.form['password'] != request.form['password2']:
        error = 'The two passwords do not match'
    elif get_user_id(request.form['username']) is not None:
        error = 'The username is already taken'
    else:
        g.db.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",  # Use parameterized query
                     (request.form['username'], request.form['email'], hash_password(request.form['password'])))
        g.db.commit()
        flash('You were successfully registered and can login now')
        return redirect(url_for('login'))
    return render_template('register.html', error=error)

@app.route('/api/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('search'))

################################################################################
# Security Functions
################################################################################

def hash_password(password):
    """Hash a password using md5 encryption."""
    password_bytes = password.encode('utf-8')
    hash_object = hashlib.md5(password_bytes)
    password_hash = hash_object.hexdigest()
    return password_hash

def verify_password(stored_hash, password):
    """Verify a stored password against one provided by user. Returns a boolean."""
    password_hash = hash_password(password)
    return stored_hash == password_hash


################################################################################
# Main
################################################################################
if __name__ == '__main__':
    # Try to connect to the database first
    try:
        connect_db()
    except Exception as e:
        print(f"Error connecting to database: {e}", file=sys.stderr)
        sys.exit(1)
    # Run the server
    # debug=True enables automatic reloading and better messaging, only for development
    app.run(host="0.0.0.0", port=8080, debug=DEBUG)