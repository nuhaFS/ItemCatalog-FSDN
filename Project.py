#!/usr/bin/env python3

import os
from os.path import join, dirname, realpath
from flask import (
    Flask,
    flash,
    render_template,
    request,
    redirect,
    jsonify,
    url_for
)
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from werkzeug.utils import secure_filename
from database_setup import Base, Shop, Items, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from oauth2client import _helpers
import httplib2
import json
from flask import make_response
import requests
from flask_wtf.csrf import CSRFProtect, CSRFError


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog App"

UPLOAD_FOLDER = join(dirname(realpath(__file__)),
                     'static/Imgs')
ALLOWED_EXTENSIONS = { 'png', 'jpg', 'jpeg', 'gif' }

app = Flask(__name__)

csrf = CSRFProtect(app)


app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
engine = create_engine('sqlite:///OurShops.db?check_same_thread=False')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def savingImgs(file):
    '''Saving Imgs when uploaded to database'''
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return filename


# Updating CSS files
# Static url cache buster.
@app.context_processor
def override_url_for():
    return dict(url_for=dated_url_for)


def dated_url_for(endpoint, **values):
    if endpoint == 'static':
        filename = values.get('filename', None)
        if filename:
            file_path = os.path.join(endpoint, filename)
            values['q'] = int(os.stat(file_path).st_mtime)
    return url_for(endpoint, **values)


# LogOut function
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print('Access Token is None')
        response = make_response(json.dumps('''Current user not
                                 connected.'''), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print('In gdisconnect access token is %s', access_token)
    print('User name is: ')
    print(login_session['username'])
    url_l = 'https://accounts.google.com/o/oauth2/revoke?token='
    url_s = login_session['access_token']
    url = url_l + url_s
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('result is ')
    print(result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('''Failed to revoke token
                                 for given user.''', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# CSRF error handler
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf_error.html', reason=e.description), 400


# Login for the main page
@app.route('/login')
@csrf.exempt
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    page = '/'
    return render_template('login.html', STATE=state, page=page)


# Login for the products page
@app.route('/login/shop/<int:shop_id>/products/')
@csrf.exempt
def showLoginP(shop_id):
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    page = ''
    page += '/shop/'
    page += str(shop_id)
    page += '/products/'

    return render_template('login.html', STATE=state, page=page)


# Connecting to gplus openid credentials
@app.route('/gconnect', methods=['POST'])
@csrf.exempt
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
    result = json.loads(_helpers._from_bytes(h.request(url, 'GET')[1]))
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

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
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('''Current user is
                                 already connected.'''), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    print(data)

    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['picture'] = data['picture']

    user_id = getUserID(login_session['email'])

    if not user_id:
        user_id = createUser(login_session)

    login_session['user_id'] = user_id

    output = ''
    output += '<img src="'
    output += login_session['picture']
    output += ' " id = "profilePic" />'
    output += '</br><h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")
    return output


# Adding a new user credentials to the database
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# Retrieving user data from the database
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    user = session.query(User).filter_by(email=email).first()
    if user:
        return user.id
    else:
        return None


@app.route('/logout')
@csrf.exempt
def logout():
    logOut = gdisconnect()
    if logOut:
        return redirect(url_for('showShops'))


# JSON APIs to view shops and products
@app.route('/shops/JSON')
def shopsJSON():
    shops = session.query(Shop).all()
    return jsonify(shops=[s.serialize for s in shops])


@app.route('/shop/<int:shop_id>/products/JSON')
def productsJSON(shop_id):
    shops = session.query(Shop).filter_by(id=shop_id).one()
    products = session.query(Items).filter_by(
        shop_id=shop_id).all()
    return jsonify(products=[p.serialize for p in products])


# Show all shops
@app.route('/')
@app.route('/shop/')
def showShops():
    shops = session.query(Shop).order_by(asc(Shop.name))
    if 'username' not in login_session:
        return render_template('publicIndex.html', shops=shops)
    else:
        return render_template('Index.html', shops=shops)


# Create a new shop
@app.route('/shop/new/', methods=['GET', 'POST'])
def newShop():
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
        if 'shopPic' in request.files:
            file = request.files['shopPic']
            filename = savingImgs(file)
        else:
            filename = "ImgPlaceHolder.png"
        newShop = Shop(name=request.form['shopName'], shopImgName=filename,
                       user_id=login_session['user_id'])
        session.add(newShop)
        session.commit()
        flash("Your shop %s has been added!" % newShop.name)
        return redirect(url_for('showShops'))

    else:
        return render_template('addShop.html')


# Edit a shop
@app.route('/shop/<int:shop_id>/edit/', methods=['GET', 'POST'])
def editShop(shop_id):
    editedShop = session.query(Shop).filter_by(id=shop_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if editedShop.user_id != login_session['user_id']:
        return """<script>function myFunction()
                {alert('You are not authorized to edit this shop.
                Please create your own shop in order to edit.');}</script>
                <body onload='myFunction()'>"""

    if request.method == 'POST':
        if request.form['shopName']:
            editedShop.name = request.form['shopName']
        if 'newShopPic' in request.files:
            file = request.files['newShopPic']
            filename = savingImgs(file)
            editedShop.shopImgName = filename
        session.commit()
        flash("%s Has been edited!" % editedShop.name)
        return redirect(url_for('showShops'))

    else:
        return render_template('editShop.html', shop=editedShop)


# Delete a shop
@app.route('/shop/<int:shop_id>/delete/', methods=['GET', 'POST'])
def deleteShop(shop_id):
    shop = session.query(Shop).filter_by(id=shop_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if shop.user_id != login_session['user_id']:
        return """<script>function myFunction()
                {alert('You are not authorized to Delete this shop.');}
                </script><body onload='myFunction()'>"""
    if request.method == 'POST':
        picName = shop.shopImgName
        if picName != "ImgPlaceHolder.png":
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'],
                      shop.shopImgName))
        session.delete(shop)
        session.commit()

        flash("%s Has been deleted!" % shop.name)
        return redirect(url_for('showShops'))
    else:
        return render_template('deleteShop.html', shop=shop)


# Shop products for a certain shop
@app.route('/shop/<int:shop_id>/')
@app.route('/shop/<int:shop_id>/products/')
def showShop(shop_id):
    shop = session.query(Shop).filter_by(id=shop_id).one()
    creator = getUserInfo(shop.user_id)
    products = session.query(Items).filter_by(
        shop_id=shop_id).all()
    if 'username' not in login_session or creator.id != login_session[
                                                        'user_id']:
        return render_template('publicProductList.html',
                               shop=shop, products=products)
    else:
        return render_template('productList.html', shop=shop,
                               products=products, creator=creator)


# Add a new product
@app.route(
    '/shop/<int:shop_id>/products/new/', methods=['GET', 'POST'])
def newProduct(shop_id):
    if 'username' not in login_session:
        return redirect('/login')
    shop = session.query(Shop).filter_by(id=shop_id).one()
    if login_session['user_id'] != shop.user_id:
        return """<script>function myFunction() {alert('You are not
                authorized to add a product to this list.
                Please create your own shop in order to add
                items.');}</script><body onload='myFunction()'>"""

    if request.method == 'POST':
        if 'itemPic' in request.files:
            file = request.files['itemPic']
            filename = savingImgs(file)
        else:
            filename = "ImgPlaceHolder.png"

        newItem = Items(name=request.form['name'], description=request.form[
                        'description'], price=request.form['price'],
                        itemImgName=filename, shop_id=shop_id)
        session.add(newItem)
        session.commit()
        flash("Product: %s Has been added!" % newItem.name)
        return redirect(url_for('showShop', shop_id=shop_id))
    else:
        return render_template('newProduct.html', shop_id=shop_id)


# Edit a product
@app.route('/shop/<int:shop_id>/products/<int:product_id>/edit/',
           methods=['GET', 'POST'])
def editProduct(shop_id, product_id):
    if 'username' not in login_session:
        return redirect('/login')
    shop = session.query(Shop).filter_by(id=shop_id).one()
    editedItem = session.query(Items).filter_by(id=product_id).one()
    if login_session['user_id'] != shop.user_id:
        return """<script>function myFunction() {alert('You are not authorized
                to edit this product to this list.');}</script><body
                onload='myFunction()'>"""

    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if 'itemPic' in request.files:
            request.files['itemPic']
            file = request.files['itemPic']
            filename = savingImgs(file)
            editedItem.itemImgName = filename
        session.commit()
        flash("Product: %s Has been edited!" % editedItem.name)
        return redirect(url_for('showShop', shop_id=shop_id))

    else:

        return render_template(
            'editProduct.html', shop_id=shop_id,
            product_id=product_id, item=editedItem)


# Delete a product
@app.route('/shop/<int:shop_id>/products/<int:product_id>/delete',
           methods=['GET', 'POST'])
def deleteProduct(shop_id, product_id):
    if 'username' not in login_session:
        return redirect('/login')
    shop = session.query(Shop).filter_by(id=shop_id).one()
    product = session.query(Items).filter_by(id=product_id).one()
    if login_session['user_id'] != shop.user_id:
        return """<script>function myFunction() {alert('You are not authorized
                to edit this product to this list.');}</script><body
                onload='myFunction()'>"""

    if request.method == 'POST':
        picName = product.itemImgName
        if picName != "ImgPlaceHolder.png":
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'],
                      product.itemImgName))
        session.delete(product)
        session.commit()
        flash("Product: %s Has been deleted!" % product.name)
        return redirect(url_for('showShop', shop_id=shop_id))
    else:
        return render_template('deleteProduct.html',
                               product=product, shop_id=shop_id)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
