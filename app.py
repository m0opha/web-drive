from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, abort
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from datetime import timedelta
from dotenv import load_dotenv
from functools import wraps
import bcrypt
import mimetypes
import os
import re
from flask import Response

from user import UserDatabase


load_dotenv()


_DB_NAME = os.getenv("DB")
BASE_UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER")

if not BASE_UPLOAD_FOLDER:
    raise RuntimeError("UPLOAD_FOLDER environment variable must be set")

app_secret = os.getenv("SECRET_KEY")
if not app_secret:
    raise RuntimeError("SECRET_KEY environment variable must be set")

os.makedirs(BASE_UPLOAD_FOLDER, exist_ok=True)


db = UserDatabase(_DB_NAME)
app = Flask(__name__)
app.secret_key = app_secret
app.wsgi_app = ProxyFix(app.wsgi_app, x_prefix=1)  # Allow passthrough behind nginx reverse proxy

app.config.update(
    SESSION_COOKIE_SECURE=False, #False if passthrough behind nginx reverse proxy
    SESSION_COOKIE_HTTPONLY=False,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH= 21 * 1024 ** 3 
)



def get_folder_size(path):
    total = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            total += os.path.getsize(fp)
    return total


def get_user_folder(username):
    folder = os.path.join(BASE_UPLOAD_FOLDER, username)
    os.makedirs(folder, exist_ok=True)
    return folder


def get_mime_type(filepath):
    mime, _ = mimetypes.guess_type(filepath)
    return mime if mime and "certificate" not in mime else "text/plain"


def safe_user_path(username, filename):
    user_folder = os.path.realpath(get_user_folder(username))
    full_path = os.path.realpath(os.path.join(user_folder, filename))

    if not full_path.startswith(user_folder + os.sep):
        return None

    return full_path


########################################################
# Routes settings
########################################################
def login_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorator


@app.route('/')
def inicio():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('User or password are incorrect.', 'danger')
            return render_template('login.html')

        user = db.getUser(username)

        if (user and
            bcrypt.checkpw(
                password.encode(),
                user["password"].encode()
            )):

            session.clear()
            session['username'] = username
            session.permanent = True
            app.permanent_session_lifetime = timedelta(hours=24)

            get_user_folder(username)
            flash(f'Welcome {username}!', 'success')
            return redirect(url_for('dashboard'))

        flash('User or password are incorrect.', 'danger')

    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    username = session.get('username')
    user_folder = get_user_folder(username)
    files = os.listdir(user_folder)

    return render_template(
        'dashboard.html',
        username=username,
        files=files
    )


@app.route('/logout')
def logout():
    username = session.get('username')
    session.clear()
    flash(f'Goodbye {username}', 'info')
    return redirect(url_for('login'))


@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'files' not in request.files:
        flash('File not found.', 'danger')
        return redirect(url_for('dashboard'))

    username = session.get('username')
    user_folder = get_user_folder(username)
    files = request.files.getlist('files')

    # Calcular tamaño desde Content-Length en vez de seek
    upload_size = request.content_length or 0
    size = get_folder_size(user_folder)
    MAX_CAPACITY = 20 * 1024 ** 3

    if size + upload_size > MAX_CAPACITY:
        flash("Maximum capacity exceeded.", "danger")
        return redirect(url_for('dashboard'))

    for file in files:
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            if not filename:
                flash('Invalid filename.', 'danger')
                continue
            file.save(os.path.join(user_folder, filename))

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return '', 200
    return redirect(url_for('dashboard'))



@app.route('/download/<filename>')
@login_required
def download_file(filename):
    username = session.get('username')
    file_path = safe_user_path(username, filename)

    if file_path is None or not os.path.isfile(file_path):
        flash('File not found.', 'danger')
        return redirect(url_for('dashboard'))

    return send_file(
        file_path,
        as_attachment=True,
        download_name=os.path.basename(file_path)
    )


@app.route('/stream/<filename>')
@login_required
def stream_file(filename):
    username = session.get('username')
    file_path = safe_user_path(username, filename)

    if file_path is None or not os.path.isfile(file_path):
        abort(404)

    file_size = os.path.getsize(file_path)
    mime = get_mime_type(file_path)
    range_header = request.headers.get('Range')

    if not range_header:
        # Sin Range → entrega completa normal
        return send_file(file_path, mimetype=mime)

    # Parsear Range: bytes=start-end
    match = re.search(r'bytes=(\d+)-(\d*)', range_header)
    if not match:
        abort(416)

    start = int(match.group(1))
    end   = int(match.group(2)) if match.group(2) else file_size - 1
    end   = min(end, file_size - 1)
    length = end - start + 1

    def generate():
        with open(file_path, 'rb') as f:
            f.seek(start)
            remaining = length
            chunk = 65536  # 64 KB por chunk
            while remaining > 0:
                data = f.read(min(chunk, remaining))
                if not data:
                    break
                remaining -= len(data)
                yield data

    headers = {
        'Content-Range':  f'bytes {start}-{end}/{file_size}',
        'Accept-Ranges':  'bytes',
        'Content-Length': str(length),
        'Content-Type':   mime,
    }

    return Response(generate(), status=206, headers=headers)


@app.route('/delete/<filename>', methods=['POST'])
@login_required
def delete_file(filename):
    username = session.get('username')
    file_path = safe_user_path(username, filename)

    if file_path is None:
        flash('Invalid filename.', 'danger')
        return redirect(url_for('dashboard'))

    if os.path.isfile(file_path):
        os.remove(file_path)
        flash('File removed.', 'success')
    
    else:
        flash('File not found.', 'danger')

    return redirect(url_for('dashboard'))


@app.route('/see/<filename>')
@login_required
def see_file(filename):
    username = session.get('username')
    file_path = safe_user_path(username, filename)

    if (file_path is None ) or (not os.path.isfile(file_path)):
        abort(404)

    return send_file(
        file_path,
        mimetype=get_mime_type(file_path)
    )

@app.route('/edit/<filename>', methods=['POST'])
@login_required
def edit_file(filename):
    username = session.get('username')
    file_path = safe_user_path(username, filename)
    if file_path is None:
        return 'Invalid filename', 400
    if not os.path.isfile(file_path):
        return 'File not found', 404

    content_type = request.content_type or ''

    if 'text/' in content_type or 'json' in content_type:
        # Texto: decodificar con UTF-8
        content = request.get_data(as_text=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
    else:
        # Binario: escribir bytes crudos (imágenes, PDFs, etc.)
        content = request.get_data(as_text=False)
        with open(file_path, 'wb') as f:
            f.write(content)

    return 'OK', 200

@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    username = session.get('username')
    current = request.form.get('current_password')
    new = request.form.get('new_password')
    confirm = request.form.get('confirm_password')

    if new != confirm:
        flash('Passwords do not match.', 'danger')
        return redirect(url_for('dashboard'))

    user = db.getUser(username)
    if not bcrypt.checkpw(current.encode(), user['password'].encode()):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('dashboard'))

    new_hash = bcrypt.hashpw(new.encode(), bcrypt.gensalt()).decode()
    db.updatePassword(username, new_hash)
    flash('Password changed successfully.', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    debug_mode = os.getenv("DEBUG", "false").lower() in ("1", "true", "yes")
    app.run(
        debug=debug_mode,
        host='127.0.0.1',
        port=5000
    )
