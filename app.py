import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from flask_migrate import Migrate
import secrets
from functools import wraps
from dotenv import load_dotenv
load_dotenv() # Memuat variabel dari file .env
from urllib.parse import quote
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail as SendGridMail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, DecimalField, IntegerField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, NumberRange, Regexp

# ----------------------- Configuration -----------------------
# Variabel ini tidak lagi digunakan secara langsung untuk URI database, tapi bisa dipertahankan untuk referensi atau kegunaan lain.
# DATABASE_URL = os.environ.get('DATABASE_URL') or 'sqlite:///parfume_demo.db'
SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
WHATSAPP_NUMBER = os.environ.get('WHATSAPP_NUMBER') or ''
SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')
FLASK_DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", 'sqlite:///parfume_demo.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8) # A07: Session Management
app.config['SECRET_KEY'] = SECRET_KEY

# Konfigurasi keamanan tambahan untuk cookie di lingkungan produksi
if not FLASK_DEBUG:
    app.config['SESSION_COOKIE_SECURE'] = True  # Hanya kirim cookie melalui HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True # Mencegah akses cookie dari JavaScript
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Melindungi dari CSRF

db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "10 per hour"]
)

# ----------------------- Models -----------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    # New: role string (user | admin | superadmin)
    role = db.Column(db.String(20), default="user")

    # 2FA Fields
    two_factor_code = db.Column(db.String(6), nullable=True)
    two_factor_expires_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Keep for compatibility with existing code / migrations
    is_admin = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_superadmin(self):
        return self.role == "superadmin"

    @property
    def role_is_admin(self):
        # admin by role (include superadmin)
        return self.role in ("admin", "superadmin")


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Numeric(10,2), nullable=False)
    stock = db.Column(db.Integer, default=0)
    image_url = db.Column(db.String(300), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    added_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    product = db.relationship('Product')
    user = db.relationship('User')

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total = db.Column(db.Numeric(12,2), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    items = db.Column(db.Text)
    user = db.relationship('User')

# ----------------------- Forms -----------------------
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8), Regexp(
        r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$',
        message="Password harus mengandung huruf besar, huruf kecil, angka, dan simbol.")]) # A07: Password Strength

class LoginForm(FlaskForm):
    identifier = StringField('Username atau Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class Verify2FAForm(FlaskForm):
    """Form untuk verifikasi kode 2FA."""
    otp = StringField('Kode Verifikasi', validators=[DataRequired(), Length(min=6, max=6)])

class ProductForm(FlaskForm):
    name = StringField('Nama', validators=[DataRequired(), Length(max=150)])
    description = TextAreaField('Deskripsi')
    price = DecimalField('Harga', validators=[DataRequired(), NumberRange(min=0)])
    stock = IntegerField('Stok', validators=[DataRequired(), NumberRange(min=0)])
    image_url = StringField('URL Gambar')

class AddToCartForm(FlaskForm):
    # Form ini bisa kosong, tujuannya hanya untuk CSRF token
    pass

class AdminUserForm(FlaskForm):
    """Form untuk membuat atau mengedit user oleh Super Admin."""
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    role = StringField('Role', validators=[DataRequired()], default='admin')


# ----------------------- Helpers -----------------------
@app.context_processor
def utility_processor():
    return dict(
        now=lambda: datetime.now(),
        search=request.args.get('search', ''),
        current_user=current_user()
    )

def send_2fa_email(user_email, otp_code):
    """Mengirim email 2FA menggunakan SendGrid."""
    if not SENDGRID_API_KEY:
        app.logger.error("SENDGRID_API_KEY tidak diatur. Tidak bisa mengirim email.")
        return False
    
    message = SendGridMail(
        from_email='isrogamers@gmail.com', # Ganti dengan email terverifikasi di SendGrid
        to_emails=user_email,
        subject='Kode Verifikasi Login Anda',
        html_content=f'Gunakan kode ini untuk login: <strong>{otp_code}</strong>. Kode ini akan kedaluwarsa dalam 10 menit.'
    )
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        # SendGrid merespon dengan 202 Accepted jika berhasil menerima request
        if response.status_code == 202:
            app.logger.info(f"Email 2FA berhasil dikirim ke {user_email}, status: {response.status_code}")
            return True
        else:
            app.logger.error(f"SendGrid gagal mengirim email ke {user_email}, status: {response.status_code}, body: {response.body}")
            return False
    except Exception as e:
        app.logger.error(f"Gagal mengirim email 2FA ke {user_email}: {e}")
        return False

@app.template_filter('rupiah')
def format_rupiah(value):
    if not isinstance(value, (int, float, Decimal)):
        return value
    return f"Rp {value:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")

def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    return db.session.get(User, uid)

def login_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user():
            # Jika request asli adalah POST, lebih baik redirect ke halaman sebelumnya
            # daripada ke endpoint POST itu sendiri setelah login.
            next_url = request.referrer or url_for('index')
            if request.method == 'GET':
                next_url = request.path
            flash('Silakan login terlebih dahulu.', 'warning')
            return redirect(url_for('login', next=next_url))
        return f(*args, **kwargs)
    return wrapper

import logging # A09: Logging
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        u = current_user()
        # support legacy boolean is_admin OR new role-based admin
        if not u or (not getattr(u, 'is_admin', False) and not getattr(u, 'role_is_admin', False)):
            abort(403)
        return f(*args, **kwargs)
    return wrapper

# New decorator for super admin
def super_admin_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u or not getattr(u, 'is_superadmin', False):
            abort(403)
        return f(*args, **kwargs)
    return wrapper

# A09: Konfigurasi Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# ----------------------- Routes -----------------------
@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip().lower()
        password = form.password.data
        if User.query.filter((User.username==username)|(User.email==email)).first():
            flash('Username atau email sudah digunakan.', 'danger')
            return redirect(url_for('register'))
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Akun dibuat. Silakan login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET','POST'])
@limiter.limit("5/minute") # A04: Rate Limiting untuk login
def login():
    form = LoginForm()
    if form.validate_on_submit():
        identifier = form.identifier.data.strip()
        password = form.password.data
        user = User.query.filter((User.username==identifier)|(User.email==identifier)).first()
        if user and user.check_password(password):
            # --- START: 2FA Logic ---
            otp = str(secrets.randbelow(900000) + 100000) # Menghasilkan angka 6 digit yang aman
            user.two_factor_code = otp
            user.two_factor_expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
            db.session.commit()

            # Kirim email
            send_2fa_email(user.email, otp)

            session['user_id_for_2fa'] = user.id
            flash('Kami telah mengirimkan kode verifikasi ke email Anda.', 'info')
            return redirect(url_for('verify_2fa'))
            # --- END: 2FA Logic ---

        app.logger.warning(f"Login gagal untuk user/email: {identifier} dari IP: {get_remote_address()}") # A09: Logging
        flash('Login gagal. Periksa kredensial Anda atau coba lagi nanti.', 'danger')
    return render_template('login.html', form=form)

@app.route('/verify_2fa', methods=['GET', 'POST'])
@limiter.limit("10/minute") # Rate limit untuk mencegah brute-force OTP
def verify_2fa():
    if 'user_id_for_2fa' not in session:
        return redirect(url_for('login'))

    form = Verify2FAForm()
    if form.validate_on_submit():
        user = db.session.get(User, session['user_id_for_2fa'])
        # WORKAROUND: Paksa datetime dari DB untuk menjadi 'aware' sebelum dibandingkan
        # Ini untuk mengatasi masalah sinkronisasi skema database.
        expires_at_aware = user.two_factor_expires_at.replace(tzinfo=timezone.utc)

        if user and user.two_factor_code == form.otp.data and datetime.now(timezone.utc) < expires_at_aware:
            # Kode benar, bersihkan data 2FA dan login-kan user
            user.two_factor_code = None
            user.two_factor_expires_at = None
            db.session.commit()
            
            session.pop('user_id_for_2fa', None)
            session['user_id'] = user.id
            session.permanent = True
            
            flash(f'Login berhasil! Selamat datang, {user.username}!', 'success')
            
            # Tambahkan kembali logika redirect berbasis role di sini
            if user.is_superadmin:
                return redirect(url_for('superadmin_index'))
            elif user.role_is_admin:
                return redirect(url_for('admin_index'))
            else:
                return redirect(url_for('index'))
        else:
            flash('Kode verifikasi salah atau sudah kedaluwarsa.', 'danger')
    return render_template('verify_2fa.html', form=form)

@app.route('/resend_2fa', methods=['POST'])
@limiter.limit("2/minute") # Batasi pengiriman ulang untuk mencegah spam
def resend_2fa():
    """Mengirim ulang kode verifikasi 2FA."""
    if 'user_id_for_2fa' not in session:
        return jsonify({'success': False, 'message': 'Sesi tidak valid.'}), 400

    user = db.session.get(User, session['user_id_for_2fa'])
    if not user:
        return jsonify({'success': False, 'message': 'User tidak ditemukan.'}), 404

    # Buat dan kirim kode baru
    otp = str(secrets.randbelow(900000) + 100000) # Menghasilkan angka 6 digit yang aman
    user.two_factor_code = otp
    user.two_factor_expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    db.session.commit()

    send_2fa_email(user.email, otp)

    return jsonify({'success': True, 'message': 'Kode baru telah dikirim.'})

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Anda telah logout.', 'info')
    return redirect(url_for('index'))

@app.route('/')
def index():
    products = Product.query.order_by(Product.created_at.desc()).limit(12).all()
    return render_template('index.html', products=products)

@app.route('/products')
def products_list():
    search = request.args.get("search", "")
    page = request.args.get('page', 1, type=int)
    query = Product.query
    if search:
        query = query.filter(Product.name.like(f"%{search}%"))
    
    products_pagination = query.order_by(Product.created_at.desc()).paginate(page=page, per_page=12)
    return render_template('products.html', products_pagination=products_pagination, search=search)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    p = Product.query.get_or_404(product_id)
    form = AddToCartForm()
    return render_template('product_detail.html', product=p, form=form)

@app.route('/cart')
@login_required
def view_cart():
    u = current_user()
    items = CartItem.query.filter_by(user_id=u.id).all()
    total = sum(item.product.price * item.quantity for item in items)
    form = AddToCartForm() # Menggunakan form yang sama untuk CSRF
    return render_template('cart.html', items=items, total=total, form=form)

@app.route('/cart/add/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    u = current_user()
    p = Product.query.get_or_404(product_id)
    try:
        qty = int(request.form.get('quantity', 1))
        if qty <= 0:
            raise ValueError("Kuantitas harus lebih dari nol.")
    except (ValueError, TypeError):
        flash('Kuantitas tidak valid.', 'danger') # Pesan dari ValueError tidak akan ditampilkan, tapi ini untuk keamanan.
        return redirect(url_for('product_detail', product_id=product_id))
    if p.stock < qty:
        flash('Stok tidak cukup.', 'warning')
        return redirect(url_for('product_detail', product_id=product_id))
    item = CartItem.query.filter_by(user_id=u.id, product_id=p.id).first()
    if item:
        item.quantity += qty
    else:
        item = CartItem(user_id=u.id, product_id=p.id, quantity=qty)
        db.session.add(item)
    db.session.commit()
    flash('Berhasil menambahkan ke keranjang.', 'success')
    return redirect(url_for('view_cart'))

@app.route('/cart/remove/<int:item_id>', methods=['POST'])
@login_required
def remove_from_cart(item_id):
    u = current_user()
    item = CartItem.query.get_or_404(item_id)
    if item.user_id != u.id:
        abort(403)
    db.session.delete(item)
    db.session.commit()
    flash('Item dihapus dari keranjang.', 'info')
    return redirect(url_for('view_cart'))

@app.route('/checkout', methods=['GET','POST'])
@login_required
def checkout():
    u = current_user()
    items = CartItem.query.filter_by(user_id=u.id).all()
    if not items:
        flash('Keranjang kosong.', 'warning')
        return redirect(url_for('view_cart'))

    # Cek stok
    for item in items:
        if item.product.stock < item.quantity:
            flash(f"Stok tidak cukup untuk produk {item.product.name}.", 'danger')
            return redirect(url_for('view_cart'))

    # Simpan pesanan ke database
    total = sum(item.product.price * item.quantity for item in items)
    item_details = []
    for item in items:
        item_details.append(f"{item.product.name} (x{item.quantity})")
        # Kurangi stok produk
        # Kita bisa menggunakan item.product karena sudah ada relasinya
        item.product.stock -= item.quantity

    new_order = Order(
        user_id=u.id,
        total=total,
        items="; ".join(item_details)
    )
    db.session.add(new_order)

    # Hapus keranjang setelah pesanan dibuat
    for item in items:
        db.session.delete(item)
    
    # Lakukan commit sekali saja di akhir setelah semua operasi berhasil
    db.session.commit()

    # Buat pesan WhatsApp
    message_lines = ["Halo, saya mau pesan parfum berikut:"]
    message_lines.extend([f"- {line}" for line in item_details])
    message_lines.append(f"\nTotal Pesanan: {format_rupiah(total)}")
    whatsapp_message = "\n".join(message_lines)

    whatsapp_url = f"https://wa.me/{WHATSAPP_NUMBER}?text={quote(whatsapp_message)}"
    return redirect(whatsapp_url)

# ----------------------- Admin -----------------------
@app.route('/admin')
@admin_required
def admin_index():
    product_count = Product.query.count()
    user_count = User.query.count()
    order_count = Order.query.count()
    return render_template('admin/index.html', product_count=product_count, user_count=user_count, order_count=order_count)

@app.route('/admin/products')
@admin_required
def admin_products():
    page = request.args.get('page', 1, type=int)
    products_pagination = Product.query.order_by(Product.id.desc()).paginate(page=page, per_page=10)
    return render_template('admin/products.html', products_pagination=products_pagination)

@app.route('/admin/products/new', methods=['GET','POST'])
@admin_required
def admin_new_product():
    form = ProductForm()
    if form.validate_on_submit():
        p = Product(
            name=form.name.data.strip(),
            description=form.description.data.strip(),
            price=form.price.data,
            stock=form.stock.data,
            image_url=form.image_url.data or None
        )
        db.session.add(p)
        db.session.commit()
        flash('Produk berhasil dibuat.', 'success')
        return redirect(url_for('admin_products'))
    return render_template('admin/new_product.html', form=form)

@app.route('/admin/products/edit/<int:product_id>', methods=['GET','POST'])
@admin_required
def admin_edit_product(product_id):
    p = Product.query.get_or_404(product_id)
    form = ProductForm(obj=p)
    if form.validate_on_submit():
        p.name = form.name.data.strip()
        p.description = form.description.data.strip()
        p.price = form.price.data
        p.stock = form.stock.data
        p.image_url = form.image_url.data or None
        db.session.commit()
        flash('Produk diperbarui.', 'success')
        return redirect(url_for('admin_products'))
    return render_template('admin/edit_product.html', form=form, product=p)

@app.route('/admin/products/delete/<int:product_id>', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    p = Product.query.get_or_404(product_id)
    db.session.delete(p)
    db.session.commit()
    flash('Produk dihapus.', 'info')
    return redirect(url_for('admin_products'))

@app.route('/admin/users')
@admin_required
def admin_users():
    page = request.args.get('page', 1, type=int)
    users_pagination = User.query.order_by(User.id.desc()).paginate(page=page, per_page=10)
    return render_template('admin/users.html', users_pagination=users_pagination)

@app.route('/admin/orders')
@admin_required
def admin_orders():
    page = request.args.get('page', 1, type=int)
    orders_pagination = Order.query.order_by(Order.id.desc()).paginate(page=page, per_page=15)
    return render_template('admin/orders.html', orders_pagination=orders_pagination, page=page)

# ----------------------- Super Admin Routes -----------------------
@app.route('/superadmin')
@super_admin_required
def superadmin_index():
    """Dashboard khusus untuk Super Admin."""
    product_count = Product.query.count()
    user_count = User.query.count()
    order_count = Order.query.count()
    admin_count = User.query.filter(User.role == "admin").count()
    superadmin_count = User.query.filter(User.role == "superadmin").count()
    return render_template(
        'admin/superadmin_index.html',
        product_count=product_count,
        user_count=user_count,
        order_count=order_count,
        admin_count=admin_count,
        superadmin_count=superadmin_count
    )

@app.route('/superadmin/users')
@super_admin_required
def superadmin_manage_users():
    """Halaman untuk mengelola semua pengguna (termasuk admin)."""
    users = User.query.order_by(User.id.desc()).all()
    return render_template('admin/superadmin_users.html', users=users)

@app.route('/superadmin/users/add', methods=['GET', 'POST'])
@super_admin_required
def superadmin_add_user():
    """Menambahkan user baru (bisa sebagai admin atau user biasa) dengan aman."""
    form = AdminUserForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        role = form.role.data

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username atau email sudah ada.", "danger")
        else:
            new_user = User(username=username, email=email, role=role, is_admin=(role in ['admin', 'superadmin']))
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash(f"User '{username}' dengan role '{role}' berhasil ditambahkan!", "success")
            return redirect(url_for('superadmin_manage_users'))

    return render_template('admin/superadmin_add_admin.html', form=form)

@app.route('/superadmin/users/set_role/<int:user_id>/<string:new_role>', methods=['POST'])
@super_admin_required
def superadmin_set_role(user_id, new_role):
    """Mengubah role seorang user (misal: menjadi admin atau user biasa)."""
    user = User.query.get_or_404(user_id)
    if user.role == "superadmin":
        flash('Tidak dapat mengubah role Super Admin lain melalui aksi ini.', 'warning')
        return redirect(url_for('superadmin_manage_users'))

    if new_role not in ['user', 'admin', 'superadmin']:
        flash('Role tidak valid.', 'danger')
        return redirect(url_for('superadmin_manage_users'))

    user.role = new_role
    user.is_admin = (new_role in ['admin', 'superadmin'])
    db.session.commit()
    flash(f'Role {user.username} telah diubah menjadi {new_role}.', 'success')
    return redirect(url_for('superadmin_manage_users'))

# ----------------------- Utilities -----------------------
def ensure_admin():
    # ====================================================
    # 1. CREATE SUPERADMIN DEFAULT
    # ====================================================
    superadmin = User.query.filter_by(role="superadmin").first()
    if not superadmin:
        superadmin = User(
            username='superadmin',
            email='superadmin@example.com',
            role='superadmin',
            is_admin=True
        )
        superadmin.set_password('super123')
        db.session.add(superadmin)
        db.session.commit()
        print('Created default SUPERADMIN -> superadmin / super123')
    else:
        print("SUPERADMIN already exists, skip creation.")


    # ====================================================
    # 2. CREATE ADMIN DEFAULT (CEK BERDASARKAN USERNAME)
    # ====================================================
    existing_admin = User.query.filter_by(username="admin").first()

    if not existing_admin:
        admin = User(
            username='admin',
            email='admin@example.com',
            role='admin',
            is_admin=True
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print('Created default ADMIN -> admin / admin123')
    else:
        print("ADMIN already exists, skip creating default admin.")


    # ====================================================
    # 3. MIGRATE USER LAMA YANG is_admin=True MENJADI role='admin'
    # ====================================================
    try:
        legacy_admins = User.query.filter(
            User.is_admin == True,
            User.role == 'user'
        ).all()

        for la in legacy_admins:
            la.role = 'admin'

        if legacy_admins:
            db.session.commit()
            print(f'Migrated {len(legacy_admins)} legacy admins to role=admin')

    except Exception:
        db.session.rollback()
        print("Migration skipped due to missing columns or errors.")


# ----------------------- CSRF ERROR HANDLER -----------------------
from flask_wtf.csrf import CSRFError

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('Form tidak valid (CSRF). Silakan muat ulang halaman dan coba lagi.', 'danger')
    return redirect(request.referrer or url_for('index'))


# ----------------------- CLI / Startup -----------------------
@app.cli.command("seed-db")
def seed_db():
    """Mengisi database dengan data awal (admin dan produk sampel)."""
    import click
    
    # Hapus fungsi ensure_admin() yang tidak aman dan gunakan CLI
    if not User.query.filter_by(role="superadmin").first():
        click.echo("Membuat akun superadmin default...")
        superadmin = User(username='superadmin', email='isrogamers@gmail.com', role='superadmin', is_admin=True)
        superadmin.set_password('Isr@402209') # Ganti dengan password yang lebih aman atau buat interaktif
        db.session.add(superadmin)
        click.echo(click.style("Akun superadmin dibuat: superadmin / super123", fg="yellow"))
    else:
        click.echo("Akun superadmin sudah ada.")

    if Product.query.count() == 0:
        click.echo("Membuat produk sampel...")
        samples = [
            {'name':'Aurora Bloom Eau de Parfum','description':'A floral mix with bergamot and jasmine.','price':'450000','stock':10,'image_url':'https://source.unsplash.com/featured/?perfume'},
            {'name':'Midnight Oud','description':'Warm woody oud with spicy undertones.','price':'750000','stock':5,'image_url':'https://source.unsplash.com/featured/?fragrance'},
            {'name':'Citrus Whisper','description':'Fresh citrus with a hint of musk.','price':'300000','stock':15,'image_url':'https://source.unsplash.com/featured/?citrus'},
        ]
        for s in samples:
            p = Product(name=s['name'], description=s['description'], price=Decimal(s['price']), stock=s['stock'], image_url=s['image_url'])
            db.session.add(p)
        click.echo(click.style(f"{len(samples)} produk sampel berhasil dibuat.", fg="green"))
    else:
        click.echo("Produk sudah ada, tidak perlu membuat produk sampel.")
        
    db.session.commit()
    click.echo(click.style("Proses seeding database selesai.", fg="green"))

@app.cli.command("init-db")
def init_db_command():
    """Menghapus tabel yang ada dan membuat yang baru."""
    import click
    if click.confirm('Ini akan menghapus semua data. Apakah Anda yakin?'):
        db.drop_all()
        db.create_all()
        click.echo(click.style('Database telah diinisialisasi ulang.', fg='green'))



if __name__ == '__main__':
    # Blok ini hanya untuk development lokal.
    # Untuk production di PythonAnywhere, server WSGI yang akan menjalankan 'app'.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=FLASK_DEBUG)
