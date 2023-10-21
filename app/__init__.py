from flask import Flask, render_template, redirect, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_session import Session
from datetime import datetime
from .forms import LoginForm, RegisterForm, ProductsForm, SettingsForm
from flask_login import LoginManager, login_user, UserMixin, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy.exc import IntegrityError


app = Flask(__name__)
app.config["SECRET_KEY"] = '1234'
app.config['SESSION_TYPE'] = 'filesystem'
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///app.db'

Session(app)
db = SQLAlchemy(app)
login = LoginManager(app)
migrate = Migrate(app, db)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, nullable=False, unique=True)
    name = db.Column(db.String, nullable=False, unique=True)
    photo = db.Column(db.String, nullable=False, default='/static/images/images.jpg')
    password = db.Column(db.String, nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    role = db.Column(db.String, nullable=False, default='user')

    def generate_cache(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Products(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    price = db.Column(db.Float, nullable=False)
    photo = db.Column(db.String, nullable=False, default='/static/images/images.jpg')


@login.user_loader
def user_loader(user_id):
    return User.query.get(user_id)


@app.route('/')
def home():
    products = Products.query.all()
    return render_template("home.html", products=products)


@app.route('/profile', methods=['POST', "GET"])
@login_required
def profile():
    return render_template('profile.html', user=current_user)


@app.route('/profile_settings', methods=['POST', 'GET'])
@login_required
def settings():
    form = SettingsForm()
    if form.validate_on_submit():
        image = form.photo.data
        name = form.name.data
        email = form.email.data
        password = form.password.data

        if image.filename != '':
            image.save(f'app/static/image/{image.filename}')
            current_user.photo = f'/static/image/{image.filename}'

        current_user.name = name
        current_user.email = email
        current_user.generate_cache(password)

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return render_template('registration.html', title='Sign Up',
                                   form=form, message='Username or email are already used')

        return redirect('/profile')

    return render_template('profile_settings.html', user=current_user, form=form)


@app.route('/registration', methods=['POST', 'GET'])
def registration():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        image = request.files['image']
        if image.filename == '':
            user = User(name=name, email=email)
        else:
            image.save(f'app/static/images/{image.filename}')
            user = User(name=name, email=email, photo=f'/static/images/{image.filename}')
        user.generate_cache(password)
        '''try:
            db.session.add(user)
            db.session.commit()
        except IntegrityError:
'''
        db.session.add(user)
        db.session.commit()
        return redirect('/')
    return render_template('registration.html', form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user is None or not user.check_password(password):
            return redirect('/login')
        login_user(user, remember=form.remember.data)
        return redirect('/')
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect('/login')


@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if current_user.role == 'admin':
        form = ProductsForm()
        if form.validate_on_submit():
            name = form.name.data
            price = form.price.data
            image = request.files['image']
            if image.filename == '':
                product = Products(name=name, price=price)
                db.session.add(product)
                db.session.commit()
            else:
                image.save(f'app/static/images/{image.filename}')
                product = Products(name=name, price=price, photo=f'/static/images/{image.filename}')
                db.session.add(product)
                db.session.commit()
                return redirect('/')
        return render_template('add_product.html', form=form)
    else:
        return redirect('/')


@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    if current_user.role == 'admin':
        product = Products.query.get(product_id)
        if product:
            db.session.delete(product)
            db.session.commit()
        return redirect('/')
    else:
        return redirect('/')


@app.route('/products/<int:id>')
def products_page(user_id):
    products = Products.query.get(user_id)
    return render_template('products.html', id=user_id, name=products.name, photo=products.photo,
                           price=products.price)


@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        data = request.form['search']
        results = Products.query.filter(Products.name.ilike(f'%{data}%')).all()
        return render_template('home.html', products=results)
    else:
        return render_template('search.html')


@app.route('/filter', methods=['GET', 'POST'])
def filter_products():
    if request.method == 'POST':

        low_price = request.form.get('low_price', type=float)
        high_price = request.form.get('high_price', type=float)

        products = Products.query.filter(
            Products.price >= low_price,
            Products.price <= high_price,
        ).all()
    else:
        products = Products.query.all()

    return render_template('filter.html', products=products)


@app.route('/buy/<int:id>', methods=['POST'])
def buy(id):
    product = Products.query.get(id)
    if product:
        if 'basket' not in session:
            session['basket'] = [{'id': product.id, 'name': product.name, 'price': product.price}]
        else:
            session['basket'].append({'id': product.id, 'name': product.name, 'price': product.price})
        print(session['basket'])
        return redirect(url_for('basket'))
    else:
        return "Product not found", 404


@app.route('/basket')
def basket():
    print(session['basket'])
    total_price = 0
    if 'basket' in session.keys():
        total_price = sum(i['price'] for i in session['basket'])
    return render_template('basket.html', basket=session['basket'], total_price=total_price)


@app.route('/remove_from_basket/<int:id>', methods=['POST'])
def remove_from_basket(id):
    if 'basket' in session:
        session['basket'] = [product for product in session['basket'] if product['id'] != id]
    return redirect(url_for('basket'))


@app.route('/checkout', methods=['POST'])
def checkout():
    if 'basket' in session:
        basket_items = session['basket']
        total_price = sum(item['price'] for item in basket_items)
        return render_template('checkout.html', basket_items=basket_items, total_price=total_price)
    else:
        return "Your basket is empty."


@app.route('/thank_you', methods=['POST'])
def thank_you():
    basket_items = []
    total_price = 0
    if 'basket' in session:
        basket_items = session['basket']
        total_price = sum(item['price'] for item in basket_items)
        session.pop('basket')
    return render_template('thank_you.html', basket_items=basket_items, total_price=total_price)
