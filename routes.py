from flask import render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db
from app.models import User, Movie
from app.forms import LoginForm, MovieForm
from app.utils.log_handler import log_error
from app.utils.ftp_handler import upload_image_via_ftp
from werkzeug.utils import secure_filename # Asegúrate de importar esto en routes.py

@app.route('/')
def index():
    movies = Movie.query.all()
    return render_template('index.html', movies=movies)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/movie/<int:movie_id>')
def movie_detail(movie_id):
    movie = Movie.query.get_or_404(movie_id)
    return render_template('movie_detail.html', movie=movie)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    movies = Movie.query.all()
    return render_template('admin.html', movies=movies)

@app.route('/add_movie', methods=['GET', 'POST'])
@login_required
def add_movie():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    form = MovieForm()
    if form.validate_on_submit():
        image_file = form.imagen.data # Obtener el archivo subido
        if image_file:
            filename = secure_filename(image_file.filename) # Usar secure_filename
            # ... (tu lógica para guardar la imagen y obtener la URL) ...
            image_url = upload_image_via_ftp(image_file) # Ejemplo de uso
        else:
            image_url = None # Manejar el caso donde no se sube imagen
        movie = Movie(
            title=form.titulo.data,
            genre=form.genre.data,
            synopsis=form.synopsis.data,
            date=form.date.data,
            image_url=image_url,
            status=form.status.data
        )
        db.session.add(movie)
        db.session.commit()
        flash('Movie added successfully!', 'success')
        return redirect(url_for('admin'))
    return render_template('add_movie.html', form=form)

@app.errorhandler(404)
def page_not_found(e):
    log_error(e)
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    log_error(e)
    return render_template('500.html'), 500