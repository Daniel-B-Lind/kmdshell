import os
import pty
import select
from pathlib import Path
from datetime import datetime

from flask import (
    Flask, render_template_string, request, redirect, url_for,
    send_file, flash, jsonify, abort
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_socketio import SocketIO, join_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import psutil


class Config:
    PORT = 52961

    # !!! CHANGE APP_SECRET BEFORE DEPLOYING !!!
    SECRET_KEY = os.environ.get('APP_SECRET', 'dev-secret-kmdshell')
    ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')

    # Either define a plaintext password here,
    # or make sure KMD_HASH is set to a valid scrypt hash
    # or that KMD_PWD is set to your plaintext password of choice
    # before deploying. Default password fallback 'mallorca'
    ADMIN_HASH = os.environ.get('KMD_HASH') or \
        generate_password_hash(os.environ.get('KMD_PWD', 'mallorca'))

    BASE_DIR = Path(os.environ.get('BASE_DIR', '/')).resolve()
    UPLOAD_DIR = Path(os.environ.get('UPLOAD_DIR', '/tmp/uploads'))

    # Set to True if you're going to rely on a reverse proxy of some kind
    # to access the webshell. Cloudflared temporary tunnels warmly recommended.
    ENFORCE_PROXY = False
    TRUSTED_PROXIES = ['127.0.0.1', '::1']
    REQUIRED_HEADER = 'X-Forwarded-For'


def _configure_async_patching():
    """
    Patches engineio and socketio to force 'threading' mode.
    Required for PyInstaller environments where this is liable to fail.
    """
    import engineio

    _emode = getattr(engineio, 'async_modes', [])
    if not isinstance(_emode, list):
        _emode = list(_emode)
    if 'threading' not in _emode:
        engineio.async_modes = _emode + ['threading']

    try:
        engineio.asyncio = None
    except Exception:
        # i literally don't care
        pass

    # Enforce async_mode='threading'
    _OrigServer = engineio.Server

    class PyInstallerSafeServer(_OrigServer):
        def __init__(self, *args, **kwargs):
            kwargs['async_mode'] = 'threading'
            super().__init__(*args, **kwargs)

    engineio.Server = PyInstallerSafeServer

    # Force python-socketio into threading mode,
    # if we need to
    # TODO: ...Is this even necessary anymore?
    try:
        import socketio as _sio
        _smode = getattr(_sio, 'async_modes', [])
        if 'threading' not in _smode:
            _sio.async_modes = list(_smode) + ['threading']
    except ImportError:
        pass


_configure_async_patching()


class SystemMonitor:
    """
    Primitive task manager to show processes and
    CPU usage.
    """

    @staticmethod
    def get_stats():
        return {
            'cpu': psutil.cpu_percent(interval=0.1),
            'mem': psutil.virtual_memory().percent,
            'disk': psutil.disk_usage('/').percent
        }

    @staticmethod
    def get_processes(limit=15):
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                procs.append(p.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        # Sort by CPU usage descending
        return sorted(procs, key=lambda x: x.get('cpu_percent') or 0, reverse=True)[:limit]


class FileManager:
    """
    File browser with upload/download functionality.
    """

    @staticmethod
    def resolve(path_str):
        # Resolves against BASE_DIR to prevent traversal.
        # Wouldn't want security vulnerabilities in a webshell, after all..
        try:
            target = (Config.BASE_DIR / path_str).resolve()
            if target != Config.BASE_DIR and \
                    Config.BASE_DIR not in target.parents:
                raise ValueError("Path traversal detected")
            return target
        except Exception:
            raise ValueError("Invalid path")

    @staticmethod
    def human_size(n):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if abs(n) < 1024.0:
                return f"{n:3.1f}{unit}"
            n /= 1024.0
        return f"{n:.1f}PB"

    @staticmethod
    def get_listing(target_path):
        entries = []
        try:
            with os.scandir(target_path) as it:
                for e in it:
                    try:
                        st = e.stat()
                    except OSError:
                        continue  # Skip unreadable files

                    rel_path = os.path.relpath(e.path, Config.BASE_DIR) \
                        .replace('\\', '/')
                    is_dir = e.is_dir()

                    if is_dir:
                        # Quick dirty count of children (slow on big dirs..)
                        try:
                            count = sum(1 for _ in os.scandir(e.path))
                            size_str = f"{count} items"
                        except OSError:
                            size_str = "?"
                    else:
                        size_str = FileManager.human_size(st.st_size)

                    entries.append({
                        'name': e.name,
                        'rel': rel_path,
                        'is_dir': is_dir,
                        'size_readable': size_str,
                        'mtime_readable': datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    })
        except OSError:
            return None  # probably a permission issue

        # Sort: Directories first, then alphabetical
        entries.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
        return entries


class PtyManager:
    """
    This is the "interactive shell" part of the webshell
    """
    SESSIONS = {}

    @classmethod
    def create_session(cls, sid):
        pid, fd = pty.fork()
        if pid == 0:
            # Try to find a working shell..
            shell_choices = [os.environ.get('SHELL'), '/bin/bash', '/bin/dash', '/bin/sh']

            for shell in shell_choices:
                if shell and os.path.exists(shell):
                    try:
                        os.execvp(shell, [shell])
                    except Exception:
                        continue  # try next one

            # no shells available? give up
            # TODO: fallback to basic POST shell instead of interactive Pty
            os._exit(1)
        else:
            cls.SESSIONS[sid] = {'pid': pid, 'fd': fd}
            return fd

    @classmethod
    def close_session(cls, sid):
        sess = cls.SESSIONS.pop(sid, None)
        if sess:
            try:
                os.close(sess['fd'])
            except OSError:
                pass

    @classmethod
    def get_fd(cls, sid):
        return cls.SESSIONS.get(sid, {}).get('fd')


# -- Initialize web server ---
app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

SocketIO.async_modes = ['threading']
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins='*')

login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Login plumbing
class User(UserMixin):
    def __init__(self, id): self.id = id


@login_manager.user_loader
def load_user(userid):
    return User(userid) if userid == Config.ADMIN_USER else None


# Middleware for proxy enforcement (if requested)
@app.before_request
def security_checks():
    if not Config.ENFORCE_PROXY:
        # we don't care? okay
        return None

    client_ip = request.remote_addr
    if client_ip not in Config.TRUSTED_PROXIES:
        app.logger.error(f"Refused untrusted IP: {client_ip}")
        return jsonify({"error": "403", "message": "Forbidden"}), 403

    if Config.REQUIRED_HEADER not in request.headers:
        # Forge bad request response
        app.logger.warning(f"Trusted IP {client_ip} missing header {Config.REQUIRED_HEADER}")
        return jsonify({"error": "400", "message": "Bad Request"}), 400


# Navbar template processor
@app.context_processor
def inject_nav():
    def get_nav():
        # Lazy load template logic
        brand = """
         <svg viewBox='0 0 24 24' width='28' height='28' xmlns='http://www.w3.org/2000/svg'>
          <rect width='24' height='24' rx='4' fill='#0b3a66'/>
          <path d='M6 8h12v2H6zM6 12h8v2H6z' fill='#8bd3ff'/>
         </svg>
        """
        links = ""
        if current_user.is_authenticated:
            links = f"""
            <a class='btn btn-light btn-sm me-1' href='{url_for('dashboard')}'>Dashboard</a>
            <a class='btn btn-light btn-sm me-1' href='{url_for('shell')}'>Shell</a>
            <a class='btn btn-light btn-sm me-1' href='{url_for('files')}'>Files</a>
            <a class='btn btn-danger btn-sm me-2' href='{url_for('logout')}'>Logout</a>
            """
        else:
            links = f"<a class='btn btn-light btn-sm me-2' href='{url_for('login')}'>Login</a>"

        return TEMPLATES['NAV'].format(brand=brand, links=links)
    return dict(nav_html=get_nav())


# --- App Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')
        if u == Config.ADMIN_USER and check_password_hash(Config.ADMIN_HASH, p):
            login_user(User(u))
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template_string(TEMPLATES['LOGIN'])


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def dashboard():
    stats = SystemMonitor.get_stats()
    return render_template_string(TEMPLATES['DASHBOARD'], **stats)


@app.route('/api/processes')
@login_required
def processes_api():
    return jsonify(SystemMonitor.get_processes())


@app.route('/files', defaults={'path': ''})
@app.route('/files/<path:path>')
@login_required
def files(path):
    try:
        target = FileManager.resolve(path)
    except ValueError:
        abort(403)

    if target.is_file():
        return send_file(str(target), as_attachment=True)

    entries = FileManager.get_listing(target)
    if entries is None:
        flash("Permission denied or directory missing", "warning")
        entries = []

    # Build breadcrumbs
    parts = path.strip('/').split('/') if path else []
    crumbs = [('/', '')]
    for i, part in enumerate(parts):
        if part:
            crumbs.append((part, '/'.join(parts[:i+1])))

    return render_template_string(
        TEMPLATES['FILES'],
        entries=entries,
        current_rel=path,
        breadcrumbs=crumbs
    )


@app.route('/files/action/download/<path:path>')
@login_required
def download(path):
    try:
        target = FileManager.resolve(path)
        if not target.is_file(): abort(404)
        return send_file(str(target), as_attachment=True)
    except ValueError:
        abort(403)


@app.route('/files/action/upload/<path:path>', methods=['POST'])
@login_required
def upload(path):
    try:
        target = FileManager.resolve(path)
        if not target.is_dir():
            abort(400)

        f = request.files.get('file')
        if f and f.filename:
            fname = secure_filename(f.filename)
            f.save(str(target / fname))
            flash(f'Uploaded {fname}', 'success')
        else:
            flash('No file selected', 'warning')
    except Exception as e:
        flash(f'Error: {e}', 'danger')
    return redirect(url_for('files', path=path))


@app.route('/files/action/delete/<path:path>', methods=['POST'])
@login_required
def delete(path):
    try:
        target = FileManager.resolve(path)
        if target.is_file():
            target.unlink()
            flash('Deleted file', 'success')
        else:
            flash('Directory deletion disabled for safety', 'warning')
    except Exception as e:
        flash(f'Error: {e}', 'danger')

    # Redirect to parent...
    parent = os.path.dirname(path)
    return redirect(url_for('files', path=parent))


@app.route('/shell')
@login_required
def shell():
    return render_template_string(TEMPLATES['SHELL'])


# --- Socketio for PTY ---
@socketio.on('connect', namespace='/pty')
def pty_connect():
    if not current_user.is_authenticated:
        return False

    sid = request.sid
    fd = PtyManager.create_session(sid)
    join_room(sid)

    # Background reader thread
    def read_output():
        while True:
            # if the session broke for some reason, exit early
            curr_fd = PtyManager.get_fd(sid)
            if not curr_fd or curr_fd != fd:
                break

            try:
                # nonblocking select check
                r, _, _ = select.select([fd], [], [], 0.1)
                if fd in r:
                    data = os.read(fd, 2048)
                    if not data:
                        break  # EOF?

                    try:
                        # enforce utf-8, replace invalid chars
                        payload = data.decode('utf-8', 'replace')
                    except Exception:
                        payload = str(data)

                    socketio.emit('output', payload, room=sid, namespace='/pty')
            except OSError:
                break

        PtyManager.close_session(sid)

    socketio.start_background_task(read_output)


@socketio.on('input', namespace='/pty')
def pty_input(data):
    fd = PtyManager.get_fd(request.sid)
    if not fd:
        return

    # Normalize input with some *pythonic shenanigans.*
    payload = data.get('d') if isinstance(data, dict) else data
    if isinstance(payload, str):
        payload = payload.encode()

    try:
        os.write(fd, payload)
    except OSError:
        pass


@socketio.on('disconnect', namespace='/pty')
def pty_disconnect():
    PtyManager.close_session(request.sid)


# --- html templates ---
# vibecoded with prejudice. it's just html. only god can judge me.
TEMPLATES = {
    'NAV': """
    <nav class='navbar navbar-dark bg-primary mb-3'>
      <div class='container'>
        <div class='d-flex align-items-center gap-2'>
          {brand}
          <div>
            <div class='navbar-brand mb-0 h5' style='line-height:1'>KMDShell</div>
            <div class='small text-muted'>it's pronounced KMDS hell</div>
          </div>
        </div>
        <div class='d-flex align-items-center'>{links}</div>
      </div>
    </nav>
    <script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js'></script>
    """,

    'LOGIN': """
    <!doctype html><html><head><meta charset='utf-8'><title>Login</title>
    <link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/bootswatch@5.3.2/dist/darkly/bootstrap.min.css'>
    <style>.card{max-width:400px;margin:10vh auto}</style></head>
    <body>{{ nav_html|safe }}
    <div class='card p-4'>
      <h4 class='mb-3'>Authenticate</h4>
      {% for m in get_flashed_messages() %}<div class='alert alert-warning'>{{ m }}</div>{% endfor %}
      <form method='post'>
        <input name='username' class='form-control mb-2' placeholder='User' required autofocus>
        <input name='password' type='password' class='form-control mb-3' placeholder='Password' required>
        <button class='btn btn-primary w-100'>Sign in</button>
      </form>
    </div></body></html>
    """,

    'DASHBOARD': """
    <!doctype html><html><head><title>Dashboard</title>
    <link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/bootswatch@5.3.2/dist/darkly/bootstrap.min.css'>
    </head><body>{{ nav_html|safe }}
    <div class='container'>
      <div class='row g-3 text-center'>
        {% for label, val in [('CPU', cpu), ('RAM', mem), ('DISK', disk)] %}
        <div class='col-md-4'><div class='card p-3'><h5>{{label}}</h5><div class='display-6'>{{val}}%</div></div></div>
        {% endfor %}
      </div>
      <h4 class='mt-4'>Top Processes</h4>
      <table class='table table-dark table-striped' id='procs'>
        <thead><tr><th>PID<th>Name<th>CPU<th>MEM</tr></thead><tbody></tbody>
      </table>
    </div>
    <script>
    setInterval(async () => {
        const res = await fetch('/api/processes');
        const data = await res.json();
        document.querySelector('#procs tbody').innerHTML = data.map(p => 
            `<tr><td>${p.pid}<td>${p.name}<td>${(p.cpu_percent||0).toFixed(1)}%<td>${(p.memory_percent||0).toFixed(1)}%`
        ).join('');
    }, 2500);
    </script></body></html>
    """,

    'FILES': """
    <!doctype html><html><head><title>Files</title>
    <link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/bootswatch@5.3.2/dist/darkly/bootstrap.min.css'>
    <style>a{text-decoration:none} .crumbs a{color:#8bd3ff}</style></head>
    <body>{{ nav_html|safe }}
    <div class='container'>
      <div class='d-flex justify-content-between mb-2'>
        <h4>Files</h4>
        <div class='crumbs'>
          {% for n, l in breadcrumbs %}
             {% if not loop.last %}<a href='{{url_for("files", path=l)}}'>{{n}}</a> / 
             {% else %}<strong>{{n}}</strong>{% endif %}
          {% endfor %}
        </div>
      </div>
      
      {% for m in get_flashed_messages(with_categories=true) %}
        <div class='alert alert-{{m[0]}}'>{{ m[1] }}</div>
      {% endfor %}

      <form action='{{ url_for("upload", path=current_rel) }}' method='post' enctype='multipart/form-data' class='mb-3 d-flex gap-2'>
         <input type='file' name='file' class='form-control w-50'>
         <button class='btn btn-primary'>Upload</button>
      </form>

      <div class='card p-2'>
        <table class='table table-dark table-hover mb-0'>
          <thead><tr><th>Name<th>Size<th>Modified<th>Actions</tr></thead>
          <tbody>
          {% for e in entries %}
            <tr>
              <td>
                <a href='{{ url_for("files", path=e.rel) }}'>{{ "📁" if e.is_dir else "📄" }} {{ e.name }}</a>
              </td>
              <td>{{ e.size_readable }}</td>
              <td>{{ e.mtime_readable }}</td>
              <td>
                {% if not e.is_dir %}
                <a href='{{ url_for("download", path=e.rel) }}' class='btn btn-sm btn-outline-light'>DL</a>
                <form action='{{ url_for("delete", path=e.rel) }}' method='POST' style='display:inline' onsubmit='return confirm("Delete?")'>
                  <button class='btn btn-sm btn-danger'>Del</button>
                </form>
                {% endif %}
              </td>
            </tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    </div></body></html>
    """,

    'SHELL': """
    <!doctype html><html><head><title>Shell</title>
    <link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/bootswatch@5.3.2/dist/darkly/bootstrap.min.css'>
    <link rel='stylesheet' href='https://unpkg.com/xterm/css/xterm.css' />
    <style>#terminal{height:75vh;border-radius:6px;overflow:hidden}</style></head>
    <body>{{ nav_html|safe }}
    <div class='container'><div id='terminal' class='bg-black'></div></div>
    <script src="https://cdn.socket.io/4.8.1/socket.io.min.js"></script>
    <script src='https://unpkg.com/xterm/lib/xterm.js'></script>
    <script src='https://unpkg.com/xterm-addon-fit/lib/xterm-addon-fit.js'></script>
    <script>
      const socket = io('/pty', {transports: ['websocket']});
      const term = new Terminal({cursorBlink:true, theme:{background:'#000'}});
      const fit = new (window.FitAddon.FitAddon || window.FitAddon)();
      
      term.loadAddon(fit);
      term.open(document.getElementById('terminal'));
      
      // Auto-resize logic
      const doFit = () => { try { fit.fit(); } catch(e){} };
      window.addEventListener('resize', doFit);
      setTimeout(doFit, 100);
      socket.on('connect', doFit);

      // IO
      socket.on('output', d => term.write(d));
      term.onData(d => socket.emit('input', d));
    </script></body></html>
    """
}


if __name__ == "__main__":
    print("[*] KMDShell Active")
    print(f"[*] Base Dir: {Config.BASE_DIR}")
    host = '127.0.0.1' if Config.ENFORCE_PROXY else '0.0.0.0'
    socketio.run(app, host=host, port=Config.PORT)

