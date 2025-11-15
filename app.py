import os
import sqlite3
from flask import Flask, render_template, request, Response, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from dotenv import load_dotenv
from functools import wraps
import hashlib
from urllib.parse import urlparse
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(256)  # Sets a random key of 256 bytes.

# Configure the SQLite database
db_path = os.path.join(os.path.dirname(__file__), 'trump.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database
db = SQLAlchemy(app)

# Example Model (Table)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

# Function to run the SQL script if database doesn't exist
def initialize_database():
    if not os.path.exists('trump.db'):
        with sqlite3.connect('trump.db') as conn:
            cursor = conn.cursor()
            with open('trump.sql', 'r') as sql_file:
                sql_script = sql_file.read()
            cursor.executescript(sql_script)
            print("Database initialized with script.")

# If user does not have their "user_id" in the session token, it will redirect you to login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Python Decorator for Flask to be able to identify if the user is an administrator
# Assumes person with ID of 1 is Admin.
# 
# If user is not the Admin, redirects them to login.
def is_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' in session and session['user_id'] == 1:
            return f(*args, **kwargs)
        else:
            return redirect(url_for('login', next=request.url))
    return decorated_function

# Forces HTTPS even in development mode.
@app.before_request
def https_redirect():
    if not request.is_secure:
        url = request.url.replace("http://", "https://", 1)
        code = 301
        return redirect(url, code=code)

# Existing routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/quotes')
def quotes():
    return render_template('quotes.html')

@app.route('/sitemap')
@login_required
def sitemap():
    return render_template('sitemap.html')
    
@app.route('/admin_panel')
@is_admin
def admin_panel():
    return render_template('admin_panel.html')

# Route to handle redirects based on the destination query parameter
@app.route('/redirect', methods=['GET'])
def redirect_handler():
    destination = request.args.get('destination')

    destinationParsed = urlparse(destination)
    currentURL = urlparse(request.base_url)

    destinationPath = destinationParsed.path
    destinationNetloc = destinationParsed.netloc
    
    currentURLnetloc = currentURL.netloc
    
    # This works if either:
    # - BaseURL Net Location of the site (ex. [https://127.0.0.1:5000]/test) equals the destination (ex. [https://127.0.0.1:5000]/different_part_of_site) 
    # - NetLocation doesn't exist due to it only being a relative path (ex. /comments/)

    # This will fail on:
    # - Using different URLs (ex. https://google.com)
    # - Using different URL schemas (ftp://127.0.0.1)
    # - Using auth combination bypasses (ex. https://127.0.0.1:5000@attackersite.zip)

    if((currentURLnetloc == destinationNetloc) or (not destinationNetloc and destinationPath)):
        return redirect(destination, code=302)
    else:
        return "Invalid destination", 400


@app.route('/comments', methods=['GET', 'POST'])
@login_required
def comments():
    if request.method == 'POST':
        username = request.form['username']
        comment_text = request.form['comment']

        # Insert comment into the database
        insert_comment_query = text("INSERT INTO comments (username, text) VALUES (:username, :text)")
        db.session.execute(insert_comment_query, {'username': username, 'text': comment_text})
        db.session.commit()
        return redirect(url_for('comments'))

    # Retrieve all comments to display
    comments_query = text("SELECT username, text FROM comments")
    comments = db.session.execute(comments_query).fetchall()
    return render_template('comments.html', comments=comments)

@app.route('/download', methods=['GET'])
@login_required
def download():
    # Get the filename from the query parameter
    file_name = request.args.get('file', '')

    # Set base directory to where your docs folder is located
    base_directory = os.path.join(os.path.dirname(__file__), 'docs')
    print(base_directory)

    # Construct the file path to attempt to read the file
    file_path = os.path.abspath(os.path.join(base_directory, file_name))

    # Ensure that the file path is within the base directory
    if not file_path.startswith(base_directory):
       return "Unauthorized access attempt!", 403

    print(os.path.basename(file_path))
    print(file_path)
    # Try to open the file securely
    try:
        with open(file_path, 'rb') as f:
            response = Response(f.read(), content_type='application/octet-stream')
            response.headers['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
            return response
    except(FileNotFoundError, IsADirectoryError):
        return "File not found", 404
    except PermissionError:
        return "Permission denied while accessing the file", 403
        
@app.route('/downloads', methods=['GET'])
@login_required
def download_page():
    return render_template('download.html')


@app.route('/profile/<int:user_id>', methods=['GET'])
@login_required
def profile(user_id):
    sql = text("SELECT * FROM users WHERE id = :user_id")
    user = db.session.execute(sql, {'user_id': user_id}).fetchone()

    try:
        userId = user[0]
    except:
        userId = None

    try:
        currentUserId = session['user_id']
    except:
        currentUserId = None

    if userId is not None and currentUserId is not None and userId == currentUserId:
        query_cards = text("SELECT * FROM carddetail WHERE id = :user_id")
        cards = db.session.execute(query_cards, {'user_id': user_id}).fetchall()
        return render_template('profile.html', user=user, cards=cards)
    else:
        return render_template('profile.html', error="User not found or unauthorized access."), 403
        
from flask import request

@app.route('/search', methods=['GET'])
@login_required
def search():
    query = request.args.get('query')
    return render_template('search.html', query=query)

@app.route('/forum')
@login_required
def forum():
    try:
        return render_template('forum.html')
    except:
        return redirect('/') 

# Add login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()


        passwordHashed = hashlib.sha256(password.encode('utf-8')).hexdigest()

        sql = text("SELECT * FROM users WHERE username = :username AND password = :password")
        user = db.session.execute(sql, {'username': username, 'password': passwordHashed}).fetchone()

        if user:
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('profile', user_id=user.id))
        else:
            error = 'Invalid Credentials. Please try again.'
            return render_template('login.html', error=error)

    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove user session
    flash('You were successfully logged out', 'success')
    return redirect(url_for('index'))

# Test route to demonstrate debug mode vulnerability
@app.route('/test-error')
@login_required
@is_admin
def test_error():
    # This will intentionally cause a ZeroDivisionError
    result = 1 / 0
    return "This will never execute"
    
from flask import session

if __name__ == '__main__':
    initialize_database()  # Initialize the database on application startup if it doesn't exist
    with app.app_context():
        db.create_all()  # Create tables based on models if they don't already exist
    app.run(debug=os.getenv('FLASK_DEBUG', 'False') == 'True', ssl_context='adhoc')