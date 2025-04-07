import os
import logging
import sys
import io
from smtplib import SMTP_SSL
from unittest import result

from flask import Flask, current_app, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
import pyodbc
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from email.mime.text import MIMEText
import smtplib

from gmai_api import send_email
from utils.log_handler import log_error

# Asegurar codificación UTF-8 para stdout y stderr
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Importaciones de módulos locales
from forms import MovieForm
from error_handler import recibir_correos_error  # Importar la función

# Definir las credenciales del correo
EMAIL_USER = '23300031@uttt.edu.mx'
EMAIL_PASS = 'Dormilon00'  # Tu contraseña de aplicación
ADMIN_EMAIL = '23300031@uttt.edu.mx'  # o el que uses

# Rutas del proyecto
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'app', 'templates')
UPLOAD_FOLDER = 'static/uploads'

# Configuración de la aplicación Flask
app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.secret_key = 'tu_clave_secreta'  # ¡Cambia esto por una clave segura!
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, UPLOAD_FOLDER)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', EMAIL_USER)
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', EMAIL_PASS)
app.config['MAIL_ASCII_ATTACHMENTS'] = False

# Inicializar Flask-Mail
mail = Mail(app)

# Configuración de logging
logging.basicConfig(filename='errores.log', level=logging.ERROR)
app.logger.setLevel(logging.ERROR)

# Configuración de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configuración de la base de datos SQL Server
#SERVER = r'IVµN\MSSQLSERVER02'
#DATABASE = 'cine_db'
#DRIVER = '{ODBC Driver 17 for SQL Server}'

# Funciones auxiliares
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


DATABASE_SERVER = 'sql.bsite.net\\MSSQL2016'
DATABASE_NAME = 'cobos_'  # Asumo que este es el nombre de tu base de datos
DATABASE_USERNAME = 'cobos_'
DATABASE_PASSWORD = 'cobos123'

def get_db_connection():
    try:
        conn_str = (
            f'DRIVER={{ODBC Driver 17 for SQL Server}};'  # Asegúrate de tener este driver instalado
            f'SERVER={DATABASE_SERVER};'
            f'DATABASE={DATABASE_NAME};'
            f'UID={DATABASE_USERNAME};'
            f'PWD={DATABASE_PASSWORD};'
        )
        conn = pyodbc.connect(conn_str)
        return conn
    except pyodbc.Error as ex:
        sqlstate = ex.args[0]
        print(f"Error al conectar a la base de datos: {sqlstate}")
        return None


def format_datetime(value, format='%Y'):
    if value is None:
        return ''
    return value.strftime(format)


app.jinja_env.filters['strftime'] = format_datetime


# Función para enviar correos electrónicos (usando smtplib directamente)
def send_email(subject, body, sender, recipients, password):
    msg = MIMEText(body, 'plain', 'utf-8')  # Especificamos UTF-8 para el cuerpo
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ', '.join(recipients)

    # Forzar la codificación a UTF-8
    msg.set_charset('utf-8')

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
            smtp_server.login(sender, password)
            smtp_server.sendmail(sender, recipients, msg.as_string())
        return "¡Mensaje enviado!"
    except Exception as e:
        return f"Error al enviar el correo: {e}"

def send_error_email(error_message):
    subject = "Error en la Aplicación Cartelera"
    body = f"Se ha producido el siguiente error en la aplicación:\n\n{error_message}"
    current_app.logger.info("Correo de error enviado al administrador.")
    logging.info("Correo de error enviado exitosamente.")
    sender = EMAIL_USER
    recipients = [ADMIN_EMAIL]  # Asegúrate de usar ADMIN_EMAIL para el administrador
    password = EMAIL_PASS
    result = send_email(subject, body, sender, recipients, password)
    return result

def manejar_error_y_notificar(error_message, exception=None):
    logging.error(error_message, exc_info=True)
    app.logger.error(error_message, exc_info=True)
    log_error(error_message)  # Usar log_error de log_handler

@app.route('/test_log_error')
def test_log_error():
    test_message = "Este es un mensaje de error de prueba con caracteres como óéíúáñ."
    log_error(test_message)
    return f"Resultado del envío de correo de error: {result}"  

@app.route('/test_send_error_email')
def test_send_error_email():
    test_message = "Este es un mensaje de error de prueba con caracteres como óéíúáñ."
    result = send_error_email(test_message)
    return f"Resultado del envío de correo de error: {result}"

# ... (resto de tu código) ...
def manejar_error_y_notificar(error_message, exception=None):
    logging.error(error_message, exc_info=True)
    app.logger.error(error_message, exc_info=True)
    send_error_email(error_message)


# Clases
class User(UserMixin):
    def __init__(self, id, username, password, role):
        self.id = id
        self.username = username
        self.password = password
        self.role = role


@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Usuarios WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()
        if user:
            return User(id=user[0], username=user[1], password=user[2], role=user[3])
    return None


# Rutas
@app.route('/')
def index():
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            fecha = request.args.get('fecha')
            busqueda = request.args.get('busqueda')
            genero_busqueda = request.args.get('genero')
            if fecha:
                cursor.execute(
                    'SELECT id, titulo, genero, sinopsis, imagen, estado, fecha, trailer_url FROM Pelicula WHERE fecha = ?',
                    (fecha,))
            elif busqueda:
                cursor.execute(
                    "SELECT id, titulo, genero, sinopsis, imagen, estado, fecha, trailer_url FROM Pelicula WHERE titulo LIKE ?",
                    ('%' + busqueda + '%',))
            elif genero_busqueda:
                cursor.execute(
                    "SELECT id, titulo, genero, sinopsis, imagen, estado, fecha, trailer_url FROM Pelicula WHERE genero LIKE ?",
                    ('%' + genero_busqueda + '%',))
            else:
                cursor.execute(
                    'SELECT id, titulo, genero, sinopsis, imagen, estado, fecha, trailer_url FROM Pelicula')
            peliculas = cursor.fetchall()
            conn.close()
            return render_template('index.html', peliculas=peliculas, now=datetime.now)
        else:
            error_message = "Error al conectar a la base de datos en /."
            log_error(error_message)
            return "Error al conectar a la base de datos", 500
    except Exception as e:
        log_error(f"Error inesperado en la ruta '/': {repr(e)}")
        return "Error interno del servidor", 500

@app.route('/registro', methods=['GET', 'POST'], endpoint='registro')
def registro():
    try:
        if request.method == 'POST':
            username = request.form['nombre']
            password = request.form['contraseña']
            email = request.form['email']
            role = 'user'
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                try:
                    cursor.execute('INSERT INTO Usuarios (username, password, email, role) VALUES (?, ?, ?, ?)',
                                   (username, password, email, role))
                    conn.commit()
                    conn.close()
                    flash('Registro exitoso. Por favor, inicia sesión.')
                    return redirect(url_for('login'))
                except Exception as db_e:
                    conn.rollback()  # Revertir cualquier cambio en caso de error en la base de datos
                    conn.close()
                    log_error(f"Error al insertar usuario en /registro: {db_e}")
                    flash('Error al registrar el usuario.', 'danger')
                    return render_template('registro.html', now=datetime.now)
            else:
                log_error("Error al conectar a la base de datos en /registro.")
                flash('Error al conectar a la base de datos.', 'danger')
                return "Error al conectar a la base de datos", 500
        return render_template('registro.html', now=datetime.now)
    except Exception as e:
        log_error(f"Error inesperado en la ruta '/registro': {repr(e)}")
        flash('Error interno del servidor durante el registro.', 'danger')
        return "Error interno del servidor", 500

@app.route('/login', methods=['GET', 'POST'], endpoint='login')
def login():
    try:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                try:
                    cursor.execute('SELECT * FROM Usuarios WHERE username = ? AND password = ?', (username, password))
                    user = cursor.fetchone()
                    conn.close()
                    if user:
                        user_obj = User(id=user[0], username=user[1],
                                        password=user[2], role=user[3])
                        login_user(user_obj)
                        return redirect(url_for('admin' if user[3] == 'admin' else 'index'))
                    else:
                        flash('Usuario o contraseña incorrectos')
                except Exception as db_e:
                    conn.close()
                    log_error(f"Error al consultar usuario en /login: {db_e}")
                    flash('Error al iniciar sesión. Inténtalo de nuevo.', 'danger')
                    return render_template('login.html', now=datetime.now)
            else:
                log_error("Error al conectar a la base de datos en /login.")
                flash('Error al conectar a la base de datos.', 'danger')
                return "Error al conectar a la base de datos", 500
        return render_template('login.html', now=datetime.now)
    except Exception as e:
        log_error(f"Error inesperado en la ruta '/login': {repr(e)}")
        flash('Error interno del servidor durante el inicio de sesión.', 'danger')
        return "Error interno del servidor", 500

@app.route('/logout', endpoint='logout')
def logout():
    try:
        logout_user()
        return redirect(url_for('index'))
    except Exception as e:
        log_error(f"Error inesperado en la ruta '/logout': {repr(e)}")
        flash('Error al cerrar sesión.', 'danger')
        return "Error interno del servidor", 500

@app.route('/admin', endpoint='admin')
@login_required
def admin():
    if current_user.role != 'admin':
        flash('No tienes permisos para acceder a esta página.', 'danger')
        return redirect(url_for('index'))

    conn = None
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM Pelicula')  # Intencionalmente incorrecto
            peliculas = cursor.fetchall()
            conn.close()
            return render_template('admin.html', peliculas=peliculas, now=datetime.now)
        else:
            error_message = "Error al conectar a la base de datos."
            log_error(error_message)  # Usar log_error para enviar el error real
            return error_message, 500

    except pyodbc.ProgrammingError as db_error:
        log_error(f"Error de base de datos en /admin: {db_error}")  # Enviar el error específico
        if conn:
            conn.close()
        return "Error interno del servidor (base de datos)", 500

    except Exception as e:
        log_error(f"Error inesperado en /admin: {repr(e)}")  # Enviar el error específico
        if conn:
            conn.close()
        return "Error interno del servidor", 500

@app.route('/admin/add_movie', methods=['GET', 'POST'], endpoint='add_movie')
@login_required
def add_movie():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    form = MovieForm()
    try:
        if form.validate_on_submit():
            titulo = form.titulo.data
            genero = form.genero.data
            sinopsis = form.sinopsis.data
            imagen_file = form.imagen.data
            estado = form.estado.data
            fecha = form.fecha.data
            trailer_url = form.trailer_url.data

            if imagen_file and allowed_file(imagen_file.filename):
                filename = secure_filename(imagen_file.filename)
                local_filepath = os.path.join(
                    app.config['UPLOAD_FOLDER'], filename)
                try:
                    imagen_file.save(local_filepath)
                    imagen_ruta_db = os.path.join('/uploads', filename).replace('\\', '/')
                    conn = get_db_connection()
                    if conn:
                        cursor = conn.cursor()
                        try:
                            cursor.execute(
                                'INSERT INTO Pelicula (titulo, genero, sinopsis, imagen, estado, fecha, trailer_url) VALUES (?, ?, ?, ?, ?, ?, ?)',
                                (titulo, genero, sinopsis, imagen_ruta_db, estado, fecha, trailer_url))
                            conn.commit()
                            conn.close()
                            flash('Película añadida con éxito.', 'success')
                            return redirect(url_for('admin'))
                        except Exception as db_e:
                            conn.rollback()
                            conn.close()
                            log_error(f"Error al insertar película en /admin/add_movie: {db_e}")
                            flash('Error al añadir película (base de datos).', 'danger')
                            return redirect(url_for('add_movie'))
                    else:
                        log_error("Error al conectar a la base de datos en /admin/add_movie (insert).")
                        flash('Error al conectar a la base de datos.', 'danger')
                        return redirect(url_for('add_movie'))
                except Exception as local_file_err:
                    log_error(f"Error al guardar archivo local en /admin/add_movie: {repr(local_file_err)}")
                    flash('Error al guardar archivo local.', 'danger')
                    return redirect(url_for('add_movie'))
            else:
                flash('Por favor, selecciona un archivo de imagen válido.', 'warning')
        return render_template('add_movie.html', form=form, now=datetime.now)
    except Exception as e:
        log_error(f"Error inesperado en la ruta '/admin/add_movie': {repr(e)}")
        flash('Error interno del servidor al añadir película.', 'danger')
        return "Error interno del servidor", 500

@app.route('/admin/edit_movie/<int:id>', methods=['GET', 'POST'], endpoint='edit_movie')
@login_required
def edit_movie(id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT * FROM Pelicula WHERE id = ?', (id,))
            pelicula = cursor.fetchone()
            conn.close()
            if pelicula is None:
                flash('Película no encontrada.', 'danger')
                return redirect(url_for('admin'))
            form = MovieForm(obj=pelicula)
            if form.validate_on_submit():
                titulo = form.titulo.data
                genero = form.genero.data
                sinopsis = form.sinopsis.data
                imagen_file = form.imagen.data
                estado = form.estado.data
                fecha = form.fecha.data
                trailer_url = form.trailer_url.data
                imagen_ruta_db = pelicula[4]

                if imagen_file and allowed_file(imagen_file.filename):
                    filename = secure_filename(imagen_file.filename)
                    local_filepath = os.path.join(
                        app.config['UPLOAD_FOLDER'], filename)
                    try:
                        imagen_file.save(local_filepath)
                        imagen_ruta_db = os.path.join('/uploads', filename).replace('\\', '/')
                    except Exception as local_file_err:
                        log_error(f"Error al guardar archivo local en /admin/edit_movie: {repr(local_file_err)}")
                        flash('Error al guardar archivo local.', 'danger')
                        return redirect(url_for('edit_movie', id=id))

                conn = get_db_connection()
                if conn:
                    cursor = conn.cursor()
                    try:
                        cursor.execute(
                            'UPDATE Pelicula SET titulo=?, genero=?, sinopsis=?, imagen=?, estado=?, fecha=?, trailer_url=? WHERE id=?',
                            (titulo, genero, sinopsis, imagen_ruta_db, estado, fecha, trailer_url, id))
                        conn.commit()
                        conn.close()
                        flash('Película actualizada con éxito.', 'success')
                        return redirect(url_for('admin'))
                    except Exception as db_e:
                        conn.rollback()
                        conn.close()
                        log_error(f"Error al actualizar película en /admin/edit_movie: {db_e}")
                        flash('Error al actualizar la película (base de datos).', 'danger')
                        return redirect(url_for('edit_movie', id=id))
                else:
                    log_error("Error al conectar a la base de datos en /admin/edit_movie (update).")
                    flash('Error al conectar a la base de datos.', 'danger')
                    return redirect(url_for('edit_movie', id=id))
            return render_template('edit_movie.html', form=form, pelicula_id=id, pelicula=pelicula, now=datetime.now)
        except Exception as db_fetch_e:
            if conn:
                conn.close()
            log_error(f"Error al obtener película para editar en /admin/edit_movie: {db_fetch_e}")
            flash('Error al cargar la película para editar.', 'danger')
            return redirect(url_for('admin'))
    else:
        log_error("Error al conectar a la base de datos en /admin/edit_movie (initial).")
        flash('Error al conectar a la base de datos.', 'danger')
        return "Error al conectar a la base de datos", 500

@app.route('/admin/delete_movie/<int:id>', endpoint='delete_movie')
@login_required
def delete_movie(id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            try:
                cursor.execute('DELETE FROM Pelicula WHERE id = ?', (id,))
                conn.commit()
                conn.close()
                flash('Película eliminada con éxito.', 'success')
            except Exception as db_e:
                conn.rollback()
                conn.close()
                log_error(f"Error al eliminar película en /admin/delete_movie: {db_e}")
                flash('Error al eliminar película. Por favor, intenta de nuevo.', 'danger')
        else:
            log_error("Error al conectar a la base de datos en /admin/delete_movie.")
            flash('Error al conectar a la base de datos.', 'danger')
    except Exception as e:
        log_error(f"Error inesperado en la ruta '/admin/delete_movie': {repr(e)}")
        flash('Error interno del servidor al eliminar la película.', 'danger')
    return redirect(url_for('admin'))

@app.route('/cartelera', endpoint='cartelera')
def cartelera():
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    'SELECT id, titulo, genero, sinopsis, imagen, estado, fecha, trailer_url FROM Pelicula')
                peliculas = cursor.fetchall()
                conn.close()
                return render_template('cartelera.html', peliculas=peliculas, now=datetime.now)
            except Exception as db_e:
                if conn:
                    conn.close()
                log_error(f"Error al obtener películas para cartelera: {db_e}")
                return "Error al obtener datos de la base de datos", 500
        else:
            log_error("Error al conectar a la base de datos en /cartelera.")
            return "Error al conectar a la base de datos", 500
    except Exception as e:
        log_error(f"Error inesperado en la ruta '/cartelera': {repr(e)}")
        return "Error interno del servidor", 500

@app.route('/pelicula/<int:id>', endpoint='pelicula_detalles')
def pelicula_detalles(id):
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            try:
                cursor.execute('SELECT * FROM Pelicula WHERE id = ?', (id,))
                pelicula = cursor.fetchone()
                conn.close()
                if pelicula:
                    print(f"Estructura de pelicula: {pelicula}")
                    return render_template('pelicula_detalles.html', pelicula=pelicula, now=datetime.now)
                else:
                    return "Película no encontrada", 404
            except Exception as db_e:
                if conn:
                    conn.close()
                log_error(f"Error al obtener detalles de la película con ID {id}: {db_e}")
                return "Error al obtener datos de la base de datos", 500
        else:
            log_error(f"Error al conectar a la base de datos para la película con ID {id}.")
            return "Error al conectar a la base de datos", 500
    except Exception as e:
        log_error(f"Error inesperado en la ruta '/pelicula/{id}': {repr(e)}")
        return "Error interno del servidor", 500

@app.route('/compra_boletos', endpoint='compra_boletos')
def compra_boletos():
    try:
        return "Página de Compra de Boletos"
    except Exception as e:
        log_error(f"Error inesperado en la ruta '/compra_boletos': {repr(e)}")
        return "Error interno del servidor", 500


@app.route('/contacto', endpoint='contacto')
@login_required
def contacto():
    try:
        return render_template('contacto.html', now=datetime.now)
    except Exception as e:
        log_error(f"Error inesperado en la ruta '/contacto': {repr(e)}")
        return "Error interno del servidor", 500

@app.route('/procesar_errores', endpoint='procesar_errores')
def procesar_errores():
    recibir_correos_error()
    return 'Errores procesados'


# Ruta de prueba para el envío de correos
@app.route('/test_email')
def test_email():
    try:
        msg = Message(
            subject="Correo de prueba",
            sender=app.config['MAIL_USERNAME'],
            recipients=[ADMIN_EMAIL],
            body="Este es un correo electrónico de prueba.",
            charset='utf-8'  # Asegurar codificación UTF-8 también en pruebas
        )
        mail.send(msg)
        return "Correo de prueba enviado"
    except Exception as e:
        manejar_error_y_notificar(f"Error al enviar correo de prueba: {repr(e)}", e)
        return "Error al enviar correo de prueba"


@app.route('/probar_envio_error')
def probar_envio_error():
    try:
        raise Exception("Simulando un error de prueba para envío de correo")
    except Exception as e:
        send_error_email(f"Error simulado: {e}")
        return "Correo de error enviado (si todo salió bien)"


# Ejecutar la aplicación
if __name__ == '__main__':
    print("Iniciando aplicación Flask...")
    app.run(debug=True, use_reloader=False)