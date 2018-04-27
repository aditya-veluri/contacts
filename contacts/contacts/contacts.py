from flask import Flask, session, redirect, url_for, escape, request, render_template
import sys
sys.path.append("/usr/local/lib/python2.7/dist-packages/")
from passlib.apps import custom_app_context as pwd_context
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
app.secret_key = 'any random string'
#app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
	return render_template('signup.html')

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    username = request.form['username']
    password = request.form['password']
    if username is None or password is None:
        abort(400) # missing arguments
    if User.query.filter_by(username = username).first() is not None:
        abort(400) # existing user
    user = User(username = username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    #print "User getting added..."
    return render_template('login.html')

@app.route('/new_contact', methods=['GET', 'POST'])
def new_contact():
	return render_template('add_contact.html')

@app.route('/add_contact', methods=['GET', 'POST'])
def add_contact():
    username = request.form['username']
    email = request.form['email']
    cur_user = session["username"]	
    user_obj = User.query.filter_by(username=cur_user).first()
    #print "username = {} and email = {}".format(username, email)
    if username is None or email is None:
        abort(400) # missing arguments
    if ContactBook.query.filter_by(email = email, user_id = user_obj.id).first() is not None:
        abort(400) # existing email
	

    #print "user_obj = {}".format(user_obj)
    contact = ContactBook(username=username, email=email)
    user_obj.contacts.append(contact)

    db.session.add(user_obj)
    db.session.commit()
    #print "Contact added...."
    return render_template('relationship.html', flag=True)

@app.route('/show_contacts', methods=['GET', 'POST'])
def show_contacts():
	username = session["username"]
	user_obj = User.query.filter_by(username=username).first()
	#print "user_obj = {} and contacts = {}".format(user_obj, user_obj.contacts)
	return render_template('contacts.html', data=user_obj.contacts)

@app.route('/remove_contact/<contact_id>', methods=['GET', 'POST'])
def remove_contact(contact_id):
	username = session["username"]
	user_obj = User.query.filter_by(username=username).first()
	user_obj.contacts = [i for i in user_obj.contacts if str(i) != str(contact_id)]
	db.session.add(user_obj)
	db.session.commit()
	return render_template('relationship.html', flag=False)

@app.route('/edit_contact/<contact_id>', methods=['GET', 'POST'])
def edit_contact(contact_id):
	username = session["username"]
	user_obj = User.query.filter_by(username=username).first()
	contact_obj = [i for i in user_obj.contacts if str(i) == str(contact_id)][0]
	return render_template('edit_contact.html', c=contact_obj)	

@app.route('/save_contact/<contact_id>', methods=['GET', 'POST'])
def save_contact(contact_id):
    username = request.form['username']
    email = request.form['email']
    cur_user = session["username"]	
    user_obj = User.query.filter_by(username=cur_user).first()
    if username is None or email is None:
        abort(400) # missing arguments
    if ContactBook.query.filter_by(email = email, user_id = user_obj.id).first() is not None:
        abort(400) # existing email		

    contact = ContactBook(username=username, email=email)
    user_obj.contacts = [i for i in user_obj.contacts if str(i) != str(contact_id)]
    db.session.add(user_obj)
    db.session.commit()
    user_obj.contacts.append(contact)

    db.session.add(user_obj)
    db.session.commit()
    return render_template('relationship.html', flag=True)

@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		session['username'] = request.form['username']
		return redirect(url_for('index'))
	return render_template('login.html')

@app.route('/')
def index():
	if('username' in session):
		username = session['username']
		return render_template('index.html', username=username)
	return "You are not logged in <br><a href = '/login'></b>" + "click here to log in</b></a>"

@app.route('/logout')
def logout():
	session.pop('username', None)
	return redirect(url_for('index'))

@app.route('/search_contact/<int:page_number>/<int:page_size>/<name>/<email>')
def search_db(page_number, page_size, name, email):
	offset = (page_number-1)*(page_size)
	query = ContactBook.query.order_by(ContactBook.id).filter((ContactBook.username==name) | (ContactBook.email==email)).offset(offset).limit(page_size)
	if(query is None):
		return "<b>Not contacts found for the given parameters!!!</b>"
	return render_template('search_result.html', data=query)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def __repr__(self):
        return '<User %r>' % self.username

class ContactBook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User',backref=db.backref('contacts', lazy=True, cascade="all, delete-orphan"))

    username = db.Column(db.String(80), nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)

    def __repr__(self):
        return '<User %r>' % self.username

# if __name__ == '__main__':
# 	db.create_all()
# 	app.run()
