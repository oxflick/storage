from flask import Flask, render_template, request, redirect, url_for, flash
from flask import jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Storage, SubStorage, SubStorageItem, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from flask import Response
from functools import wraps
from werkzeug import secure_filename
import os

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Storage App"

# Connect to Database and create database session
engine = create_engine('sqlite:///storageappwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Decorator for user login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in login_session:
            return f(*args, **kwargs)
        else:
            flash("You are not allowed to access there")
            return redirect(url_for('showLogin', next=request.url))
    return decorated_function     


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# Google connect 
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already '
                                            'connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
        # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # See if a user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# Facebook connect
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]


    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout, 
    # let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


#Facebook Disconnect
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"



# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None
      

# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/clearsession')
def clearSession():
    login_session.clear()
    return "Session cleared"


# JSON APIs to view Storage Information
@app.route('/storage/<storage_name>/substorage/JSON')
def storageSubStorageJSON(storage_name):
    storage = session.query(Storage
    ).filter_by(name=storage_name).one()
    storage_id = storage.id
    substorages = session.query(SubStorage
    ).filter_by(storage_id=storage_id).all()
    return jsonify(SubStorages=[i.serialize for i in substorages])


@app.route('/storages/JSON')
def storagesJSON():
    storages = session.query(Storage).all()
    return jsonify(storages=[r.serialize for r in storages])    


@app.route('/storage/<storage_name>/substorage/<substorage_name>/JSON')
def subStorageJSON(storage_name, substorage_name):
    Sub_Storage = session.query(SubStorage
    ).filter_by(name=substorage_name).one()
    return jsonify(Sub_Storage=Sub_Storage.serialize)


# XML Apis to view Storage Information
@app.route('/storages/XML')    
def storagesXML():
	storages = session.query(Storage).all()
	storages_xml = render_template('storages_template.xml', storages=storages)
        response = make_response(storages_xml)
        response.headers["Content-Type"] = "application/xml"    
        return response


@app.route('/storage/<storage_name>/substorage/XML')    
def storageSubStorageXML(storage_name):
	storage = session.query(Storage).filter_by(name=storage_name).one()
	storage_id = storage.id
        substorages = session.query(SubStorage
        ).filter_by(storage_id=storage_id).all()
	substorages_xml = render_template('substorage_template.xml', 
		                               substorages=substorages)
        response = make_response(substorages_xml)
        response.headers["Content-Type"] = "application/xml"    
        return response        
      

# Show all restaurants
@app.route('/')
@app.route('/storages')
def storagesAll():
    storage = session.query(Storage).all()
    substorage = session.query(SubStorage).all()
    if 'username' not in login_session:
        return render_template('publicstorage.html')
    else:
        return render_template('storage.html', storage=storage, 
        	                    substorage=substorage)


# Create a new storage room
@app.route('/storage/new', methods=['GET', 'POST'])
@login_required
def storageNew():            
    if request.method == 'POST':
        exists = session.query(Storage
                              ).filter_by(name=request.form['name']).first()
        if not exists:
            if request.form['name'] != '': 
    	        newStorage = Storage(name=request.form['name'], 
                            user_id=login_session['user_id'])
    	        session.add(newStorage)
    	        session.commit()
    	        flash("New Room created!")
            else:
                flash("Room Name can't be empty")
                return redirect(url_for('storageNew')) 
        else:
            flash("Room Name can't be the same")
            return redirect(url_for('storageNew'))                  
    	return redirect(url_for('storagesAll'))
    else:
    	return render_template('newstorage.html')


# Edit a storage room
@app.route('/storage/<storage_name>/edit', methods=['GET', 'POST'])
@login_required
def storageEdit(storage_name): 
    storage = session.query(Storage).filter_by(name=storage_name).one()
    if storage.user_id != login_session['user_id']:
            return "<script>function myFunction() {alert('You are not authorized to edit this storage room. Please create your own storage room in order to edit.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        exists = session.query(Storage
                    ).filter_by(name=request.form['name']).first()
        if not exists:
            if request.form['name']:
                storage.name = request.form['name']
            session.add(storage)
            session.commit()
            flash("Room name edited!")
        else:
            flash("Room Name can't be the same")
            return redirect(url_for('storageEdit', 
                                    storage_name = storage_name))    
        return redirect(url_for('storagesAll'))
    else:
        return render_template('editstorage.html', 
                                    storage_name=storage_name, item = storage)


# Delete a storage room
@app.route('/storage/<storage_name>/delete', methods=['GET', 'POST'])
@login_required
def storageDelete(storage_name): 
    storage = session.query(Storage).filter_by(name=storage_name).one()
    storage_id = storage.id
    countsubstorages = session.query(SubStorage
    ).filter_by(storage_id=storage_id).count()
    if storage.user_id != login_session['user_id']:
            return "<script>function myFunction() {alert('You are not authorized to delete this storage room. Please create your own storage room in order to delete.');}</script><body onload='myFunction()''>"
    if request.method == 'POST': 
            if countsubstorages >= 1:
                flash("This room has storages and can't be deleted")
                return redirect(url_for('storagesAll')) 
            else:    
                session.delete(storage)
                session.commit()
                flash("Room deleted!")
            return redirect(url_for('storagesAll'))
    else:
            return render_template('deletestorage.html', 
                                    storage_name=storage_name, item = storage, 
                                    countsubstorages = countsubstorages)


# Show a storage places in a storage room
@app.route('/storage/<storage_name>/substorage')
@app.route('/storage/<storage_name>')
def storageSubStorage(storage_name):
    storage = session.query(Storage).filter_by(name=storage_name).one()
    rooms = session.query(Storage).all()
    storage_id = storage.id
    creator = getUserInfo(storage.user_id)
    substorages = session.query(SubStorage).filter_by(storage_id=storage_id)
    countdata = session.query(SubStorage
    ).filter_by(storage_id=storage_id).count()
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicsubstorage.html', 
        	                    storage_name=storage_name, item = storage, 
        	                    substorages = substorages, rooms = rooms, 
        	                    countdata = countdata, creator = creator)        
    else:
    	return render_template('substorage.html', storage_name=storage_name, 
    		                    item = storage, substorages = substorages, 
    		                    rooms = rooms, countdata = countdata, 
    		                    creator = creator)  


# Show each substorage information
@app.route('/storage/<storage_name>/substorage/<substorage_name>')
@app.route('/storage/<storage_name>/<substorage_name>')
def storageSubStorageItem(storage_name, substorage_name):
    substorage = session.query(SubStorage).filter_by(name=substorage_name).one()
    creator = getUserInfo(substorage.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicsubstorageitem.html', 
        	                    substorage = substorage, creator = creator)
    else:
    	return render_template('substorageitem.html', substorage = substorage,
    	                        creator = creator)


# Create a new substorage item
@app.route('/storage/substorage/new', methods=['GET', 'POST'])
@login_required    
def newSubStorage():
    rooms = session.query(Storage).all()
    if not rooms:
        flash("you need to add a room first")
        return redirect(url_for('storagesAll')) 
    if request.method == 'POST':   
        storage = session.query(Storage
            ).filter_by(name=request.form['storage_name']).one()
        storage_id = storage.id
        exists = session.query(SubStorage
                ).filter_by(storage_id = storage_id, 
                            name=request.form['name']).first()
        if not exists: 
            if request.form['name'] == '': 
                flash("Storage name can't be empty!") 
                return render_template('newsubstorage.html', rooms = rooms)   
            else:          
                newItem = SubStorage(
                    name=request.form['name'], 
                    description=request.form['description'], 
                    storage_id=storage_id, user_id=login_session['user_id'])
                session.add(newItem)
                session.commit()
                flash("New Storage created!")
        else:
            flash("Two storages can't have same name!")
            return render_template('newsubstorage.html', rooms = rooms)    
        return redirect(url_for('storagesAll'))
    else:
        return render_template('newsubstorage.html', rooms = rooms)


#Edit substorage item
@app.route('/storage/<storage_name>/substorage/<substorage_name>/edit', 
	        methods=['GET', 'POST'])  
@login_required  
def editSubStorage(storage_name, substorage_name):
    editedSubStorage = session.query(SubStorage
    ).filter_by(name=substorage_name).one()
    storage_id = editedSubStorage.storage_id
    if editedSubStorage.user_id != login_session['user_id']:
            return "<script>function myFunction() {alert('You are not authorized to edit this sub storage. Please create your own sub storage of any room in order to edit.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
            exists = session.query(SubStorage
                ).filter_by(storage_id = storage_id, 
                            name=request.form['name']).first()
            if not exists:    
                    if request.form['name']:
                        editedSubStorage.name = request.form['name']   
                    if request.form['description']:
                        editedSubStorage.description = request.form['description']    
                    session.add(editedSubStorage)
                    session.commit()
                    flash("Sub Storage edited!")
            else:
                    flash("Two storages can't have same name!")
                    return render_template('editsubstorage.html',
                                            storage_name=storage_name, 
                                            substorage_name=substorage_name, 
                                            item=editedSubStorage)          
            return redirect(url_for('storagesAll'))
    else:
            return render_template('editsubstorage.html', 
                                    storage_name=storage_name, 
                                    substorage_name=substorage_name, 
                                    item=editedSubStorage)       


# Delete substorage Item
@app.route('/storage/<storage_name>/substorage/<substorage_name>/delete', 
	        methods=['GET', 'POST']) 
@login_required               
def deleteSubStorage(storage_name, substorage_name):
    subStorageToDelete = session.query(SubStorage
    ).filter_by(name=substorage_name).one()
    if subStorageToDelete.user_id != login_session['user_id']:
            return "<script>function myFunction() {alert('You are not authorized to delete this sub storage. Please create your own sub storage of any room in order to delete.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':    
            session.delete(subStorageToDelete)
            session.commit()
            flash("Sub Storage deleted!")
            return redirect(url_for('storagesAll'))
    else:
            return render_template(
                'deletesubstorage.html', storage_name=storage_name, 
                 substorage_name=substorage_name, item=subStorageToDelete) 


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('storagesAll'))
    else:
        flash("You were not logged in")
        return redirect(url_for('storagesAll'))


if __name__ == '__main__':
    app.debug = True
    app.secret_key = 'super_secret_key'
    app.run(host = '0.0.0.0', port = 8000)    