from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, TextAreaField, SelectField, IntegerField, BooleanField, PasswordField, DateTimeField, HiddenField
from wtforms.validators import DataRequired, Email, Length, ValidationError, Optional, NumberRange
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import uuid
from functools import wraps
import csv
import io
from flask_wtf.csrf import generate_csrf
from flask import send_from_directory
# from sqlalchemy import select, and_, text
# Pastikan import ini ada di bagian atas file
from sqlalchemy import select, and_, not_
# from datetime import datetime
# from werkzeug.utils import secure_filename
# from flask import send_file, jsonify

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'M6cabE6eUtym8ZvQpjsyGjAzhhP3xl0b'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///elearning.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf())

# Create upload directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'materi_files'), exist_ok=True)

# ================ MODELS ================
class User(UserMixin, db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='siswa')  # admin, guru, siswa
    nama_lengkap = db.Column(db.String(100), nullable=False)
    tanggal_daftar = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    # Relationships
    kelas_mengajar = db.relationship('Kelas', backref='guru', lazy=True)
    submissions = db.relationship('TugasSubmission', backref='siswa', lazy=True)
    quiz_attempts = db.relationship('QuizAttempt', backref='siswa', lazy=True)
    forum_posts = db.relationship('ForumPost', backref='author', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)
    absensi_records = db.relationship('Absensi', backref='siswa', lazy=True)
    game_scores = db.relationship('GameScore', backref='siswa', lazy=True)
    kelas_siswa = db.relationship('KelasSiswa', backref='siswa', lazy=True)
    forum_threads_created = db.relationship('ForumThread', backref='creator', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

class Kelas(db.Model):
    __tablename__ = 'kelas'

    id = db.Column(db.Integer, primary_key=True)
    nama_kelas = db.Column(db.String(100), nullable=False)
    deskripsi = db.Column(db.Text)
    guru_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    kode_kelas = db.Column(db.String(10), unique=True, nullable=False, index=True)
    tanggal_dibuat = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    # Relationships
    siswas = db.relationship('KelasSiswa', backref='kelas', lazy=True, cascade='all, delete-orphan')
    materis = db.relationship('Materi', backref='kelas', lazy=True, cascade='all, delete-orphan')
    tugas = db.relationship('Tugas', backref='kelas', lazy=True, cascade='all, delete-orphan')
    quizzes = db.relationship('Quiz', backref='kelas', lazy=True, cascade='all, delete-orphan')
    forum_threads = db.relationship('ForumThread', backref='kelas', lazy=True, cascade='all, delete-orphan')
    absensi = db.relationship('Absensi', backref='kelas', lazy=True, cascade='all, delete-orphan')
    mini_games = db.relationship('MiniGame', backref='kelas', lazy=True, cascade='all, delete-orphan')

    def get_siswa_count(self):
        return KelasSiswa.query.filter_by(kelas_id=self.id).count()

    def __repr__(self):
        return f'<Kelas {self.nama_kelas}>'

class KelasSiswa(db.Model):
    __tablename__ = 'kelas_siswa'
    __table_args__ = (db.UniqueConstraint('kelas_id', 'siswa_id'),)

    id = db.Column(db.Integer, primary_key=True)
    kelas_id = db.Column(db.Integer, db.ForeignKey('kelas.id'), nullable=False)
    siswa_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tanggal_bergabung = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<KelasSiswa kelas:{self.kelas_id} siswa:{self.siswa_id}>'

class Materi(db.Model):
    __tablename__ = 'materi'

    id = db.Column(db.Integer, primary_key=True)
    judul = db.Column(db.String(200), nullable=False)
    konten = db.Column(db.Text)
    kelas_id = db.Column(db.Integer, db.ForeignKey('kelas.id'), nullable=False)
    mata_pelajaran = db.Column(db.String(50), nullable=False)
    topik = db.Column(db.String(100))
    file_path = db.Column(db.String(255))
    file_type = db.Column(db.String(20))  # pdf, video, image, audio
    tanggal_dibuat = db.Column(db.DateTime, default=datetime.utcnow)
    urutan = db.Column(db.Integer, default=0)
    is_published = db.Column(db.Boolean, default=True)

class Quiz(db.Model):
    __tablename__ = 'quiz'

    id = db.Column(db.Integer, primary_key=True)
    judul = db.Column(db.String(200), nullable=False)
    deskripsi = db.Column(db.Text)
    kelas_id = db.Column(db.Integer, db.ForeignKey('kelas.id'), nullable=False)
    tanggal_mulai = db.Column(db.DateTime, nullable=False)
    tanggal_selesai = db.Column(db.DateTime, nullable=False)
    durasi_menit = db.Column(db.Integer, default=60)
    is_active = db.Column(db.Boolean, default=True)

    questions = db.relationship('QuizQuestion', backref='quiz', lazy=True, cascade='all, delete-orphan')
    attempts = db.relationship('QuizAttempt', backref='quiz', lazy=True)

class QuizQuestion(db.Model):
    __tablename__ = 'quiz_question'

    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    pertanyaan = db.Column(db.Text, nullable=False)
    tipe = db.Column(db.String(20), nullable=False)
    pilihan_a = db.Column(db.String(255))
    pilihan_b = db.Column(db.String(255))
    pilihan_c = db.Column(db.String(255))
    pilihan_d = db.Column(db.String(255))
    jawaban_benar = db.Column(db.String(255), nullable=False)
    poin = db.Column(db.Integer, default=10)
    urutan = db.Column(db.Integer, default=0)

class QuizAttempt(db.Model):
    __tablename__ = 'quiz_attempt'

    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    siswa_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tanggal_mulai = db.Column(db.DateTime, default=datetime.utcnow)
    tanggal_selesai = db.Column(db.DateTime)
    skor = db.Column(db.Float, default=0)
    status = db.Column(db.String(20), default='in_progress')
    jawaban = db.Column(db.JSON)

class Tugas(db.Model):
    __tablename__ = 'tugas'

    id = db.Column(db.Integer, primary_key=True)
    judul = db.Column(db.String(200), nullable=False)
    deskripsi = db.Column(db.Text, nullable=False)
    kelas_id = db.Column(db.Integer, db.ForeignKey('kelas.id'), nullable=False)
    tanggal_dibuat = db.Column(db.DateTime, default=datetime.utcnow)
    deadline = db.Column(db.DateTime, nullable=False)
    max_file_size = db.Column(db.Integer, default=5)
    allowed_extensions = db.Column(db.String(100), default='pdf,doc,docx,txt')
    is_active = db.Column(db.Boolean, default=True)

    submissions = db.relationship('TugasSubmission', backref='tugas', lazy=True)

class TugasSubmission(db.Model):
    __tablename__ = 'tugas_submission'

    id = db.Column(db.Integer, primary_key=True)
    tugas_id = db.Column(db.Integer, db.ForeignKey('tugas.id'), nullable=False)
    siswa_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    konten_text = db.Column(db.Text)
    file_path = db.Column(db.String(255))
    tanggal_submit = db.Column(db.DateTime, default=datetime.utcnow)
    nilai = db.Column(db.Float)
    feedback = db.Column(db.Text)
    status = db.Column(db.String(20), default='submitted')

class ForumThread(db.Model):
    __tablename__ = 'forum_thread'

    id = db.Column(db.Integer, primary_key=True)
    judul = db.Column(db.String(200), nullable=False)
    kelas_id = db.Column(db.Integer, db.ForeignKey('kelas.id'), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tanggal_dibuat = db.Column(db.DateTime, default=datetime.utcnow)
    is_pinned = db.Column(db.Boolean, default=False)

    posts = db.relationship('ForumPost', backref='thread', lazy=True, cascade='all, delete-orphan')

class ForumPost(db.Model):
    __tablename__ = 'forum_post'

    id = db.Column(db.Integer, primary_key=True)
    thread_id = db.Column(db.Integer, db.ForeignKey('forum_thread.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    konten = db.Column(db.Text, nullable=False)
    tanggal_dibuat = db.Column(db.DateTime, default=datetime.utcnow)

class Absensi(db.Model):
    __tablename__ = 'absensi'

    id = db.Column(db.Integer, primary_key=True)
    kelas_id = db.Column(db.Integer, db.ForeignKey('kelas.id'), nullable=False)
    siswa_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tanggal = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(10), nullable=False)
    keterangan = db.Column(db.String(255))

class Notification(db.Model):
    __tablename__ = 'notification'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    judul = db.Column(db.String(200), nullable=False)
    pesan = db.Column(db.Text, nullable=False)
    tipe = db.Column(db.String(20), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    tanggal_dibuat = db.Column(db.DateTime, default=datetime.utcnow)
    link = db.Column(db.String(255))

class MiniGame(db.Model):
    __tablename__ = 'mini_game'

    id = db.Column(db.Integer, primary_key=True)
    nama_game = db.Column(db.String(100), nullable=False)
    deskripsi = db.Column(db.Text)
    kelas_id = db.Column(db.Integer, db.ForeignKey('kelas.id'), nullable=False)
    embed_code = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)

    scores = db.relationship('GameScore', backref='game', lazy=True)

class GameScore(db.Model):
    __tablename__ = 'game_score'

    id = db.Column(db.Integer, primary_key=True)
    game_id = db.Column(db.Integer, db.ForeignKey('mini_game.id'), nullable=False)
    siswa_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    skor = db.Column(db.Integer, nullable=False)
    tanggal_main = db.Column(db.DateTime, default=datetime.utcnow)

# ================ LOGIN MANAGER ================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ================ DECORATORS ================
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Akses ditolak. Hanya admin yang diizinkan.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def guru_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin', 'guru']:
            flash('Akses ditolak. Hanya guru dan admin yang diizinkan.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def siswa_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'siswa':
            flash('Akses ditolak. Hanya siswa yang diizinkan.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ================ FORMS ================
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    nama_lengkap = StringField('Nama Lengkap', validators=[DataRequired(), Length(max=100)])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('guru', 'Guru'), ('siswa', 'Siswa')], validators=[DataRequired()])
    password = PasswordField('Password', validators=[Optional(), Length(min=6)])

    def validate_username(self, field):
        user = User.query.filter_by(username=field.data).first()
        if user and (not hasattr(self, 'edit_user_id') or user.id != self.edit_user_id):
            raise ValidationError('Username sudah digunakan.')

    def validate_email(self, field):
        user = User.query.filter_by(email=field.data).first()
        if user and (not hasattr(self, 'edit_user_id') or user.id != self.edit_user_id):
            raise ValidationError('Email sudah digunakan.')

class KelasForm(FlaskForm):
    nama_kelas = StringField('Nama Kelas', validators=[DataRequired(), Length(max=100)])
    deskripsi = TextAreaField('Deskripsi')

class MateriForm(FlaskForm):
    judul = StringField('Judul Materi', validators=[DataRequired(), Length(max=200)])
    mata_pelajaran = SelectField('Mata Pelajaran', 
                                choices=[('matematika', 'Matematika'), ('bahasa_indonesia', 'Bahasa Indonesia'), 
                                        ('ipa', 'IPA'), ('ips', 'IPS'), ('bahasa_inggris', 'Bahasa Inggris')],
                                validators=[DataRequired()])
    topik = StringField('Topik', validators=[Length(max=100)])
    konten = TextAreaField('Konten Materi')
    file = FileField('Upload File', validators=[FileAllowed(['pdf', 'doc', 'docx', 'mp4', 'mp3', 'jpg', 'png', 'gif'])])

class TugasForm(FlaskForm):
    judul = StringField('Judul Tugas', validators=[DataRequired(), Length(max=200)])
    deskripsi = TextAreaField('Deskripsi Tugas', validators=[DataRequired()])
    deadline = DateTimeField('Deadline', validators=[DataRequired()], format='%Y-%m-%dT%H:%M')

# ================ UTILITY FUNCTIONS ================
def generate_unique_kode_kelas():
    """Generate unique class code"""
    while True:
        kode = str(uuid.uuid4())[:8].upper()
        if not Kelas.query.filter_by(kode_kelas=kode).first():
            return kode

def is_user_in_kelas(user_id, kelas_id):
    """Check if user is enrolled in class"""
    return KelasSiswa.query.filter_by(siswa_id=user_id, kelas_id=kelas_id).first() is not None

def get_available_siswa_for_kelas(kelas_id):
    """Get list of students not enrolled in the class"""
    enrolled_siswa_ids = db.session.query(KelasSiswa.siswa_id).filter_by(kelas_id=kelas_id).subquery()
    
    available_siswa = User.query.filter(
        User.role == 'siswa',
        User.is_active == True,
        ~User.id.in_(enrolled_siswa_ids)
    ).order_by(User.nama_lengkap).all()
    
    return available_siswa

def get_siswa_in_kelas(kelas_id):
    """Get list of students enrolled in the class"""
    siswa_list = db.session.query(User, KelasSiswa).join(
        KelasSiswa, User.id == KelasSiswa.siswa_id
    ).filter(KelasSiswa.kelas_id == kelas_id).order_by(User.nama_lengkap).all()
    
    return siswa_list

# ================ MAIN ROUTES ================
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            if user.is_active:
                login_user(user, remember=True)
                user.last_login = datetime.utcnow()
                db.session.commit()
                flash(f'Selamat datang, {user.nama_lengkap}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Akun Anda telah dinonaktifkan.', 'error')
        else:
            flash('Username atau password salah.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        total_guru = User.query.filter_by(role='guru', is_active=True).count()
        total_siswa = User.query.filter_by(role='siswa', is_active=True).count()
        total_kelas = Kelas.query.filter_by(is_active=True).count()
        total_users = User.query.filter(User.role != 'admin').count()
        recent_users = User.query.filter(User.role != 'admin').order_by(User.tanggal_daftar.desc()).limit(5).all()
        return render_template('admin_dashboard.html', 
                             total_guru=total_guru, 
                             total_siswa=total_siswa, 
                             total_kelas=total_kelas,
                             total_users=total_users,
                             recent_users=recent_users)
    
    elif current_user.role == 'guru':
        kelas_mengajar = Kelas.query.filter_by(guru_id=current_user.id, is_active=True).all()
        total_siswa = db.session.query(KelasSiswa).join(Kelas).filter(
            Kelas.guru_id == current_user.id,
            Kelas.is_active == True
        ).count()
        return render_template('guru_dashboard.html', 
                             kelas_mengajar=kelas_mengajar, 
                             total_siswa=total_siswa)
    
    else:  # siswa
        kelas_siswa = db.session.query(Kelas).join(KelasSiswa).filter(
            KelasSiswa.siswa_id == current_user.id,
            Kelas.is_active == True
        ).all()
        
        tugas_pending = db.session.query(Tugas).join(Kelas).join(KelasSiswa).filter(
            KelasSiswa.siswa_id == current_user.id,
            Tugas.deadline > datetime.utcnow(),
            Tugas.is_active == True,
            ~Tugas.submissions.any(TugasSubmission.siswa_id == current_user.id)
        ).count()
        
        quiz_available = db.session.query(Quiz).join(Kelas).join(KelasSiswa).filter(
            KelasSiswa.siswa_id == current_user.id,
            Quiz.tanggal_mulai <= datetime.utcnow(),
            Quiz.tanggal_selesai > datetime.utcnow(),
            Quiz.is_active == True,
            ~Quiz.attempts.any(QuizAttempt.siswa_id == current_user.id)
        ).count()
        
        return render_template('siswa_dashboard.html', 
                             kelas_siswa=kelas_siswa, 
                             tugas_pending=tugas_pending,
                             quiz_available=quiz_available)

# ================ ADMIN ROUTES ================
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.filter(User.role != 'admin').order_by(User.nama_lengkap).all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_user():
    form = UserForm()
    if form.validate_on_submit():
        try:
            if not form.password.data:
                flash('Password diperlukan untuk user baru.', 'error')
                return render_template('admin_add_user.html', form=form)
            
            password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                nama_lengkap=form.nama_lengkap.data,
                role=form.role.data,
                password_hash=password_hash
            )
            db.session.add(new_user)
            db.session.commit()
            flash(f'{form.role.data.title()} "{form.nama_lengkap.data}" berhasil ditambahkan.', 'success')
            return redirect(url_for('admin_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Terjadi kesalahan: {str(e)}', 'error')
    
    return render_template('admin_add_user.html', form=form)

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserForm(obj=user)
    form.edit_user_id = user_id  # For validation
    
    if form.validate_on_submit():
        try:
            user.username = form.username.data
            user.email = form.email.data
            user.nama_lengkap = form.nama_lengkap.data
            user.role = form.role.data
            
            # Only update password if provided
            if form.password.data:
                user.password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            
            db.session.commit()
            flash(f'User "{user.nama_lengkap}" berhasil diperbarui.', 'success')
            return redirect(url_for('admin_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Terjadi kesalahan: {str(e)}', 'error')
    
    return render_template('admin_edit_user.html', form=form, user=user)

@app.route('/admin/delete_user/<int:user_id>')
@login_required
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)

    if user.role == 'admin':
        flash('Tidak dapat menghapus admin.', 'error')
    elif user.role == 'guru':
        # Check if teacher has active classes
        kelas_aktif = Kelas.query.filter_by(guru_id=user.id, is_active=True).first()
        if kelas_aktif:
            flash(f'Tidak dapat menghapus guru yang masih memiliki kelas aktif. Nonaktifkan kelasnya terlebih dahulu.', 'error')
            return redirect(url_for('admin_users'))

        try:
            db.session.delete(user)
            db.session.commit()
            flash(f'Guru "{user.nama_lengkap}" berhasil dihapus.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Terjadi kesalahan: {str(e)}', 'error')
    else:  # siswa
        try:
            db.session.delete(user)
            db.session.commit()
            flash(f'Siswa "{user.nama_lengkap}" berhasil dihapus.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Terjadi kesalahan: {str(e)}', 'error')

    return redirect(url_for('admin_users'))

@app.route('/admin/reset_password/<int:user_id>')
@login_required
@admin_required
def admin_reset_password(user_id):
    user = User.query.get_or_404(user_id)
    new_password = f"password{user.id}"  # Simple default password
    user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
    db.session.commit()
    flash(f'Password {user.nama_lengkap} telah direset ke: {new_password}', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/toggle_user/<int:user_id>')
@login_required
@admin_required
def admin_toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    status = "diaktifkan" if user.is_active else "dinonaktifkan"
    flash(f'User {user.nama_lengkap} berhasil {status}.', 'success')
    return redirect(url_for('admin_users'))

# Guru Routes
@app.route('/guru/kelas')
@login_required
@guru_required
def guru_kelas():
    if current_user.role == 'admin':
        kelas_list = Kelas.query.all()
    else:
        kelas_list = Kelas.query.filter_by(guru_id=current_user.id).all()
    return render_template('guru_kelas.html', kelas_list=kelas_list)

@app.route('/guru/add_kelas', methods=['GET', 'POST'])
@login_required
@guru_required
def guru_add_kelas():
    form = KelasForm()
    if form.validate_on_submit():
        kode_kelas = str(uuid.uuid4())[:8].upper()
        new_kelas = Kelas(
            nama_kelas=form.nama_kelas.data,
            deskripsi=form.deskripsi.data,
            guru_id=current_user.id,
            kode_kelas=kode_kelas
        )
        db.session.add(new_kelas)
        db.session.commit()
        flash(f'Kelas berhasil dibuat dengan kode: {kode_kelas}', 'success')
        return redirect(url_for('guru_kelas'))
    
    return render_template('guru_add_kelas.html', form=form)

@app.route('/guru/edit_kelas/<int:kelas_id>', methods=['GET', 'POST'])
@login_required
@guru_required
def edit_kelas(kelas_id):
    kelas = Kelas.query.get_or_404(kelas_id)

    # Hanya guru pemilik kelas atau admin yang boleh edit
    if current_user.role != 'admin' and kelas.guru_id != current_user.id:
        flash('Anda tidak memiliki izin untuk mengedit kelas ini.', 'danger')
        return redirect(url_for('guru_kelas'))

    form = KelasForm(obj=kelas)  # isi form dengan data kelas yang lama

    if form.validate_on_submit():
        kelas.nama_kelas = form.nama_kelas.data
        kelas.deskripsi = form.deskripsi.data
        db.session.commit()
        flash('Kelas berhasil diperbarui.', 'success')
        return redirect(url_for('guru_kelas'))

    return render_template('guru_edit_kelas.html', form=form, kelas=kelas)

@app.route('/guru/delete_kelas/<int:kelas_id>', methods=['POST', 'GET'])
@login_required
@guru_required
def delete_kelas(kelas_id):
    kelas = Kelas.query.get_or_404(kelas_id)

    # Hanya admin atau guru yang memiliki kelas yang bisa menghapus
    if current_user.role != 'admin' and kelas.guru_id != current_user.id:
        flash('Anda tidak memiliki izin untuk menghapus kelas ini.', 'error')
        return redirect(url_for('guru_kelas'))

    db.session.delete(kelas)
    db.session.commit()
    flash('Kelas berhasil dihapus.', 'success')
    return redirect(url_for('guru_kelas'))

@app.route('/guru/kelas/<int:kelas_id>/siswa')
@login_required
@guru_required
def guru_kelas_siswa(kelas_id):
    kelas = Kelas.query.get_or_404(kelas_id)
    if current_user.role != 'admin' and kelas.guru_id != current_user.id:
        flash('Akses ditolak.', 'error')
        return redirect(url_for('guru_kelas'))
    
    # Perbaikan: Gunakan query yang lebih jelas dan efisien
    siswa_list = User.query.join(KelasSiswa).filter(
        and_(
            KelasSiswa.kelas_id == kelas_id,
            User.role == 'siswa',
            User.is_active == True
        )
    ).order_by(User.nama_lengkap).all()
    
    return render_template('guru_kelas_siswa.html', kelas=kelas, siswa_list=siswa_list)

# ============ GURU ROUTES - PENGELOLAAN SISWA DI KELAS ============
@app.route('/guru/kelas/<int:kelas_id>/add_siswa', methods=['GET', 'POST'])
@login_required
@guru_required
def guru_add_siswa_to_kelas(kelas_id):
    """Guru menambah siswa satu per satu ke kelas"""
    kelas = Kelas.query.get_or_404(kelas_id)
    if current_user.role != 'admin' and kelas.guru_id != current_user.id:
        flash('Akses ditolak.', 'error')
        return redirect(url_for('guru_kelas'))
    
    if request.method == 'POST':
        siswa_id = request.form.get('siswa_id')
        if not siswa_id:
            flash('Pilih siswa terlebih dahulu.', 'error')
            return redirect(request.url)
        
        # Validasi siswa_id adalah integer
        try:
            siswa_id = int(siswa_id)
        except ValueError:
            flash('ID siswa tidak valid.', 'error')
            return redirect(request.url)
        
        # Cek apakah siswa ada dan aktif
        siswa = User.query.filter_by(id=siswa_id, role='siswa', is_active=True).first()
        if not siswa:
            flash('Siswa tidak ditemukan atau tidak aktif.', 'error')
            return redirect(request.url)
        
        existing = KelasSiswa.query.filter_by(kelas_id=kelas_id, siswa_id=siswa_id).first()
        if existing:
            flash('Siswa sudah terdaftar di kelas ini.', 'error')
        else:
            try:
                new_member = KelasSiswa(kelas_id=kelas_id, siswa_id=siswa_id)
                db.session.add(new_member)
                db.session.commit()
                flash(f'Siswa {siswa.nama_lengkap} berhasil ditambahkan ke kelas.', 'success')
            except Exception as e:
                db.session.rollback()
                flash('Terjadi kesalahan saat menambahkan siswa.', 'error')
        
        return redirect(url_for('guru_kelas_siswa', kelas_id=kelas_id))

    # Perbaikan: Query untuk siswa yang belum terdaftar
    siswa_terdaftar_ids = db.session.query(KelasSiswa.siswa_id).filter(
        KelasSiswa.kelas_id == kelas_id
    ).subquery()

    siswa_available = User.query.filter(
        and_(
            User.role == 'siswa',
            User.is_active == True,
            not_(User.id.in_(select(siswa_terdaftar_ids.c.siswa_id)))
        )
    ).order_by(User.nama_lengkap).all()
    
    return render_template('guru_add_siswa.html', kelas=kelas, siswa_available=siswa_available)

@app.route('/guru/kelas/<int:kelas_id>/add_all_siswa', methods=['POST'])
@login_required
@guru_required
def guru_add_all_siswa_to_kelas(kelas_id):
    """Guru menambah semua siswa yang tersedia ke kelas"""
    kelas = Kelas.query.get_or_404(kelas_id)
    if current_user.role != 'admin' and kelas.guru_id != current_user.id:
        flash('Akses ditolak.', 'error')
        return redirect(url_for('guru_kelas'))

    # Perbaikan: Query yang lebih robust
    siswa_terdaftar_ids = db.session.query(KelasSiswa.siswa_id).filter(
        KelasSiswa.kelas_id == kelas_id
    ).subquery()

    siswa_available = User.query.filter(
        and_(
            User.role == 'siswa',
            User.is_active == True,
            not_(User.id.in_(select(siswa_terdaftar_ids.c.siswa_id)))
        )
    ).all()

    if not siswa_available:
        flash('Tidak ada siswa yang tersedia untuk ditambahkan.', 'info')
    else:
        count = 0
        try:
            for siswa in siswa_available:
                new_member = KelasSiswa(kelas_id=kelas_id, siswa_id=siswa.id)
                db.session.add(new_member)
                count += 1
            
            db.session.commit()
            flash(f'{count} siswa berhasil ditambahkan ke kelas.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Terjadi kesalahan saat menambahkan siswa.', 'error')
    
    return redirect(url_for('guru_kelas_siswa', kelas_id=kelas_id))

@app.route('/guru/kelas/<int:kelas_id>/remove_siswa/<int:siswa_id>', methods=['POST'])
@login_required
@guru_required
def guru_remove_siswa_from_kelas(kelas_id, siswa_id):
    """Guru mengeluarkan siswa dari kelas"""
    kelas = Kelas.query.get_or_404(kelas_id)
    if current_user.role != 'admin' and kelas.guru_id != current_user.id:
        flash('Akses ditolak.', 'error')
        return redirect(url_for('guru_kelas'))
    
    kelas_siswa = KelasSiswa.query.filter_by(kelas_id=kelas_id, siswa_id=siswa_id).first()
    if kelas_siswa:
        siswa = User.query.get(siswa_id)
        try:
            db.session.delete(kelas_siswa)
            db.session.commit()
            flash(f'Siswa {siswa.nama_lengkap} berhasil dikeluarkan dari kelas.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Terjadi kesalahan saat mengeluarkan siswa.', 'error')
    else:
        flash('Siswa tidak ditemukan di kelas ini.', 'error')
    
    return redirect(url_for('guru_kelas_siswa', kelas_id=kelas_id))

@app.route('/guru/kelas/<int:kelas_id>/bulk_manage', methods=['POST'])
@login_required
@guru_required
def guru_bulk_manage_siswa(kelas_id):
    """Guru mengelola siswa secara bulk (tambah/hapus multiple siswa)"""
    kelas = Kelas.query.get_or_404(kelas_id)
    if current_user.role != 'admin' and kelas.guru_id != current_user.id:
        flash('Akses ditolak.', 'error')
        return redirect(url_for('guru_kelas'))
    
    action = request.form.get('action')  # 'add' atau 'remove'
    siswa_ids = request.form.getlist('siswa_ids')
    
    if not siswa_ids:
        flash('Pilih minimal satu siswa.', 'error')
        return redirect(url_for('guru_kelas_siswa', kelas_id=kelas_id))
    
    # Validasi action
    if action not in ['add', 'remove']:
        flash('Aksi tidak valid.', 'error')
        return redirect(url_for('guru_kelas_siswa', kelas_id=kelas_id))
    
    count = 0
    try:
        if action == 'add':
            for siswa_id in siswa_ids:
                # Validasi siswa_id
                try:
                    siswa_id = int(siswa_id)
                except ValueError:
                    continue
                
                # Cek apakah siswa sudah terdaftar
                existing = KelasSiswa.query.filter_by(kelas_id=kelas_id, siswa_id=siswa_id).first()
                if not existing:
                    # Cek apakah siswa valid dan aktif
                    siswa = User.query.filter_by(id=siswa_id, role='siswa', is_active=True).first()
                    if siswa:
                        new_member = KelasSiswa(kelas_id=kelas_id, siswa_id=siswa_id)
                        db.session.add(new_member)
                        count += 1
            
            db.session.commit()
            flash(f'{count} siswa berhasil ditambahkan ke kelas.', 'success')
            
        elif action == 'remove':
            for siswa_id in siswa_ids:
                try:
                    siswa_id = int(siswa_id)
                except ValueError:
                    continue
                    
                kelas_siswa = KelasSiswa.query.filter_by(kelas_id=kelas_id, siswa_id=siswa_id).first()
                if kelas_siswa:
                    db.session.delete(kelas_siswa)
                    count += 1
            
            db.session.commit()
            flash(f'{count} siswa berhasil dikeluarkan dari kelas.', 'success')
            
    except Exception as e:
        db.session.rollback()
        flash('Terjadi kesalahan saat memproses siswa.', 'error')
    
    return redirect(url_for('guru_kelas_siswa', kelas_id=kelas_id))

@app.route('/guru/kelas/<int:kelas_id>/materi')
@login_required
@guru_required
def guru_lihat_materi(kelas_id):
    kelas = Kelas.query.get_or_404(kelas_id)

    # Pastikan hanya guru yang punya akses atau admin
    if current_user.role != 'admin' and kelas.guru_id != current_user.id:
        flash("Anda tidak memiliki akses ke materi kelas ini.", "error")
        return redirect(url_for('guru_dashboard'))

    materis = Materi.query.filter_by(kelas_id=kelas_id).order_by(Materi.urutan, Materi.tanggal_dibuat).all()
    return render_template('guru_lihat_materi.html', kelas=kelas, materis=materis)

@app.route('/guru/kelas/<int:kelas_id>/materi/tambah', methods=['GET', 'POST'])
@login_required
@guru_required
def guru_tambah_materi(kelas_id):
    kelas = Kelas.query.get_or_404(kelas_id)

    # Pastikan user ini adalah guru kelas ini atau admin
    if current_user.role != 'admin' and kelas.guru_id != current_user.id:
        flash("Anda tidak punya akses untuk tambah materi di kelas ini.", "error")
        return redirect(url_for('guru_dashboard'))

    form = MateriForm()

    if form.validate_on_submit():
        # Simpan file jika ada
        filename = None
        file_type = None
        
        if form.file.data:
            f = form.file.data
            filename = secure_filename(f.filename)
            
            # Pastikan filename tidak kosong setelah secure_filename
            if not filename:
                flash('Nama file tidak valid.', 'error')
                return render_template('guru_tambah_materi.html', form=form, kelas=kelas)
            
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], 'materi_files')
            os.makedirs(upload_path, exist_ok=True)
            
            try:
                f.save(os.path.join(upload_path, filename))
                file_type = os.path.splitext(filename)[1][1:].lower() if filename else None
            except Exception as e:
                flash('Gagal menyimpan file.', 'error')
                return render_template('guru_tambah_materi.html', form=form, kelas=kelas)

        try:
            materi_baru = Materi(
                judul=form.judul.data,
                mata_pelajaran=form.mata_pelajaran.data,
                topik=form.topik.data,
                konten=form.konten.data,
                file_path=filename,
                file_type=file_type,
                kelas_id=kelas.id,
            )

            db.session.add(materi_baru)
            db.session.commit()
            flash('Materi berhasil dibuat!', 'success')
            return redirect(url_for('guru_lihat_materi', kelas_id=kelas.id))
        except Exception as e:
            db.session.rollback()
            flash('Terjadi kesalahan saat menyimpan materi.', 'error')

    return render_template('guru_tambah_materi.html', form=form, kelas=kelas)

@app.route('/guru/kelas/<int:kelas_id>/materi/<int:materi_id>/edit', methods=['GET', 'POST'])
@login_required
@guru_required
def guru_edit_materi(kelas_id, materi_id):
    kelas = Kelas.query.get_or_404(kelas_id)
    materi = Materi.query.get_or_404(materi_id)

    if (current_user.role != 'admin' and kelas.guru_id != current_user.id) or materi.kelas_id != kelas_id:
        flash("Anda tidak berhak mengedit materi ini.", "error")
        return redirect(url_for('guru_lihat_materi', kelas_id=kelas_id))

    form = MateriForm(obj=materi)

    if form.validate_on_submit():
        try:
            materi.judul = form.judul.data
            materi.mata_pelajaran = form.mata_pelajaran.data
            materi.topik = form.topik.data
            materi.konten = form.konten.data

            # Cek jika ada file baru di-upload
            if form.file.data:
                f = form.file.data
                filename = secure_filename(f.filename)
                
                if filename:  # Pastikan filename valid
                    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], 'materi_files')
                    os.makedirs(upload_path, exist_ok=True)
                    
                    try:
                        f.save(os.path.join(upload_path, filename))
                        materi.file_path = filename
                        materi.file_type = os.path.splitext(filename)[1][1:].lower()
                    except Exception as e:
                        flash('Gagal menyimpan file baru.', 'error')
                        return render_template('guru_edit_materi.html', form=form, kelas=kelas, materi=materi)

            db.session.commit()
            flash("Materi berhasil diperbarui.", "success")
            return redirect(url_for('guru_lihat_materi', kelas_id=kelas_id))
        except Exception as e:
            db.session.rollback()
            flash("Terjadi kesalahan saat memperbarui materi.", "error")

    return render_template('guru_edit_materi.html', form=form, kelas=kelas, materi=materi)

@app.route('/guru/kelas/<int:kelas_id>/materi/<int:materi_id>/hapus', methods=['POST'])
@login_required
@guru_required
def guru_delete_materi(kelas_id, materi_id):
    kelas = Kelas.query.get_or_404(kelas_id)
    materi = Materi.query.get_or_404(materi_id)

    # Pastikan guru hanya bisa hapus materi di kelasnya sendiri atau admin
    if (current_user.role != 'admin' and kelas.guru_id != current_user.id) or materi.kelas_id != kelas_id:
        flash("Anda tidak berhak menghapus materi ini.", "error")
        return redirect(url_for('guru_lihat_materi', kelas_id=kelas_id))

    try:
        db.session.delete(materi)
        db.session.commit()
        flash("Materi berhasil dihapus.", "success")
    except Exception as e:
        db.session.rollback()
        flash("Terjadi kesalahan saat menghapus materi.", "error")
        
    return redirect(url_for('guru_lihat_materi', kelas_id=kelas_id))

@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    # Pastikan filename aman
    filename = secure_filename(filename)
    return send_from_directory('uploads/materi_files', filename)

# ============ SISWA ROUTES - BERGABUNG KE KELAS ============

@app.route('/siswa/join_kelas', methods=['GET', 'POST'])
@login_required
@siswa_required
def siswa_join_kelas():
    """Siswa bergabung ke kelas menggunakan kode kelas"""
    if request.method == 'POST':
        kode_kelas = request.form.get('kode_kelas', '').strip().upper()
        
        if not kode_kelas:
            flash('Masukkan kode kelas.', 'error')
            return redirect(request.url)
        
        # Cari kelas berdasarkan kode
        kelas = Kelas.query.filter_by(kode_kelas=kode_kelas, is_active=True).first()
        if not kelas:
            flash('Kode kelas tidak valid atau kelas tidak aktif.', 'error')
            return redirect(request.url)
        
        # Cek apakah siswa sudah terdaftar di kelas ini
        existing = KelasSiswa.query.filter_by(kelas_id=kelas.id, siswa_id=current_user.id).first()
        if existing:
            flash('Anda sudah terdaftar di kelas ini.', 'info')
            return redirect(url_for('siswa_my_kelas'))
        
        # Tambahkan siswa ke kelas
        try:
            new_member = KelasSiswa(kelas_id=kelas.id, siswa_id=current_user.id)
            db.session.add(new_member)
            db.session.commit()
            flash(f'Berhasil bergabung ke kelas "{kelas.nama_kelas}".', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Terjadi kesalahan saat bergabung ke kelas.', 'error')
            
        return redirect(url_for('siswa_my_kelas'))
    
    return render_template('siswa_join_kelas.html')

@app.route('/siswa/kelas')
@login_required
@siswa_required
def siswa_my_kelas():
    """Daftar kelas yang diikuti siswa"""
    kelas_list = Kelas.query.join(KelasSiswa).filter(
        and_(
            KelasSiswa.siswa_id == current_user.id,
            Kelas.is_active == True
        )
    ).order_by(Kelas.nama_kelas).all()
    
    return render_template('siswa_my_kelas.html', kelas_list=kelas_list)

@app.route('/siswa/kelas/<int:kelas_id>')
@login_required
@siswa_required
def siswa_view_kelas(kelas_id):
    """Siswa melihat detail kelas yang diikuti"""
    # Pastikan siswa terdaftar di kelas ini
    kelas_siswa = KelasSiswa.query.filter_by(kelas_id=kelas_id, siswa_id=current_user.id).first()
    if not kelas_siswa:
        flash('Anda tidak terdaftar di kelas ini.', 'error')
        return redirect(url_for('siswa_my_kelas'))
    
    kelas = Kelas.query.get_or_404(kelas_id)
    
    # Pastikan kelas masih aktif
    if not kelas.is_active:
        flash('Kelas ini sudah tidak aktif.', 'error')
        return redirect(url_for('siswa_my_kelas'))
    
    # Ambil materi, tugas, dan quiz dari kelas ini
    materis = Materi.query.filter_by(kelas_id=kelas_id).order_by(Materi.urutan, Materi.tanggal_dibuat).all()
    tugas_list = Tugas.query.filter_by(kelas_id=kelas_id, is_active=True).order_by(Tugas.deadline).all()
    quiz_list = Quiz.query.filter_by(kelas_id=kelas_id, is_active=True).order_by(Quiz.tanggal_mulai).all()
    
    return render_template('siswa_view_kelas.html', 
                         kelas=kelas, 
                         materis=materis, 
                         tugas_list=tugas_list, 
                         quiz_list=quiz_list)

@app.route('/siswa/leave_kelas/<int:kelas_id>', methods=['POST'])
@login_required
@siswa_required
def siswa_leave_kelas(kelas_id):
    """Siswa keluar dari kelas"""
    kelas_siswa = KelasSiswa.query.filter_by(kelas_id=kelas_id, siswa_id=current_user.id).first()
    if not kelas_siswa:
        flash('Anda tidak terdaftar di kelas ini.', 'error')
    else:
        try:
            kelas = Kelas.query.get(kelas_id)
            db.session.delete(kelas_siswa)
            db.session.commit()
            flash(f'Berhasil keluar dari kelas "{kelas.nama_kelas}".', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Terjadi kesalahan saat keluar dari kelas.', 'error')
    
    return redirect(url_for('siswa_my_kelas'))

# ============ UTILITY ROUTES ============

@app.route('/api/check_kode_kelas/<kode>')
@login_required
def check_kode_kelas(kode):
    """API untuk validasi kode kelas (AJAX)"""
    kelas = Kelas.query.filter_by(kode_kelas=kode.upper(), is_active=True).first()
    if kelas:
        return jsonify({
            'valid': True,
            'nama_kelas': kelas.nama_kelas,
            'guru': kelas.guru.nama_lengkap,
            'deskripsi': kelas.deskripsi
        })
    else:
        return jsonify({'valid': False})

@app.route('/guru/kelas/<int:kelas_id>/regenerate_code', methods=['POST'])
@login_required
@guru_required
def guru_regenerate_kelas_code(kelas_id):
    """Guru regenerate kode kelas"""
    kelas = Kelas.query.get_or_404(kelas_id)
    if current_user.role != 'admin' and kelas.guru_id != current_user.id:
        flash('Akses ditolak.', 'error')
        return redirect(url_for('guru_kelas'))
    
    try:
        old_code = kelas.kode_kelas
        new_code = str(uuid.uuid4())[:8].upper()
        kelas.kode_kelas = new_code
        db.session.commit()
        flash(f'Kode kelas berhasil diperbarui dari {old_code} ke {new_code}', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Terjadi kesalahan saat memperbarui kode kelas.', 'error')
    
    return redirect(url_for('guru_kelas_siswa', kelas_id=kelas_id))

@app.route('/guru/kelas/<int:kelas_id>/export_siswa')
@login_required
@guru_required
def guru_export_siswa(kelas_id):
    """Export daftar siswa kelas ke CSV"""
    kelas = Kelas.query.get_or_404(kelas_id)
    if current_user.role != 'admin' and kelas.guru_id != current_user.id:
        flash('Akses ditolak.', 'error')
        return redirect(url_for('guru_kelas'))
    
    # Ambil daftar siswa dengan join yang lebih eksplisit
    siswa_list = db.session.query(User, KelasSiswa).join(
        KelasSiswa, User.id == KelasSiswa.siswa_id
    ).filter(
        and_(
            KelasSiswa.kelas_id == kelas_id,
            User.role == 'siswa',
            User.is_active == True
        )
    ).order_by(User.nama_lengkap).all()
    
    # Buat CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['No', 'Username', 'Email', 'Nama Lengkap', 'Tanggal Bergabung'])
    
    for i, (siswa, kelas_siswa) in enumerate(siswa_list, 1):
        writer.writerow([
            i,
            siswa.username,
            siswa.email,
            siswa.nama_lengkap,
            kelas_siswa.tanggal_bergabung.strftime('%d/%m/%Y %H:%M') if kelas_siswa.tanggal_bergabung else 'N/A'
        ])
    
    output.seek(0)
    
    # Return as downloadable file
    try:
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'siswa_kelas_{kelas.nama_kelas}_{datetime.now().strftime("%Y%m%d")}.csv'
        )
    except Exception as e:
        flash('Terjadi kesalahan saat mengexport data.', 'error')
        return redirect(url_for('guru_kelas_siswa', kelas_id=kelas_id))

# ============ DEBUG ROUTES (Hapus di production) ============
@app.route('/debug/siswa_list')
@login_required
@admin_required  # Hanya admin yang bisa akses
def debug_siswa_list():
    """Route untuk debug - melihat semua siswa aktif"""
    siswa_list = User.query.filter_by(role='siswa', is_active=True).all()
    
    debug_info = {
        'total_siswa': len(siswa_list),
        'siswa_data': []
    }
    
    for siswa in siswa_list:
        debug_info['siswa_data'].append({
            'id': siswa.id,
            'username': siswa.username,
            'nama_lengkap': siswa.nama_lengkap,
            'email': siswa.email,
            'is_active': siswa.is_active,
            'role': siswa.role
        })
    
    return jsonify(debug_info)

@app.route('/debug/kelas/<int:kelas_id>/siswa_available')
@login_required
@admin_required  # Hanya admin yang bisa akses
def debug_siswa_available(kelas_id):
    """Route untuk debug - melihat siswa yang tersedia untuk kelas tertentu"""
    kelas = Kelas.query.get_or_404(kelas_id)
    
    # Siswa yang sudah terdaftar
    siswa_terdaftar_ids = db.session.query(KelasSiswa.siswa_id).filter(
        KelasSiswa.kelas_id == kelas_id
    ).subquery()
    
    siswa_terdaftar = User.query.join(KelasSiswa).filter(
        and_(
            KelasSiswa.kelas_id == kelas_id,
            User.role == 'siswa'
        )
    ).all()
    
    # Siswa yang tersedia (belum terdaftar)
    siswa_available = User.query.filter(
        and_(
            User.role == 'siswa',
            User.is_active == True,
            not_(User.id.in_(select(siswa_terdaftar_ids.c.siswa_id)))
        )
    ).all()
    
    debug_info = {
        'kelas_info': {
            'id': kelas.id,
            'nama_kelas': kelas.nama_kelas,
            'guru': kelas.guru.nama_lengkap
        },
        'siswa_terdaftar': {
            'count': len(siswa_terdaftar),
            'data': [{'id': s.id, 'nama': s.nama_lengkap, 'username': s.username} for s in siswa_terdaftar]
        },
        'siswa_available': {
            'count': len(siswa_available),
            'data': [{'id': s.id, 'nama': s.nama_lengkap, 'username': s.username, 'is_active': s.is_active} for s in siswa_available]
        }
    }
    
    return jsonify(debug_info)
# Function to create admin account
def create_admin_account():
    """Create default admin account if it doesn't exist"""
    admin = User.query.filter_by(role='admin').first()
    if not admin:
        admin_user = User(
            username='admin',
            email='admin@elearning.com',
            nama_lengkap='Administrator',
            role='admin',
            password_hash=bcrypt.generate_password_hash('admin123').decode('utf-8'),
            is_active=True
        )
        db.session.add(admin_user)
        db.session.commit()
        print("✅ Default admin created successfully!")
        print("📧 Email: admin@elearning.com")
        print("👤 Username: admin")
        print("🔐 Password: admin123")
        print("🎯 Role: admin")
        return True
    else:
        print("ℹ️  Admin account already exists")
        print(f"👤 Username: {admin.username}")
        print(f"📧 Email: {admin.email}")
        print(f"👥 Name: {admin.nama_lengkap}")
        return False

if __name__ == '__main__':
    with app.app_context():
        # Create all database tables
        db.create_all()
        print("📊 Database tables created successfully!")
        
        # Create admin account
        create_admin_account()
        
        print("\n🚀 E-Learning System is ready!")
        print("🌐 Access the application at: http://127.0.0.1:5000")
        print("\n" + "="*50)
    
    app.run(debug=True)