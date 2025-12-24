# KMDShell
### Single-file interactive Flask-based webshell.
#### "holy heck what else is new"

Webshells are a dime a dozen nowadays, but I wanted my own server to use if the need ever struck. Decided that I might as well flesh it out with some bells and whistles. Open sourcing it from its former retirement in a random folder.

Pairs well with tunneling software. Spin it up to bind to localhost, enforce a proxy, and point Cloudflared or Ngrok at it. It's JUST like SSH, you guys!

Can be used for legitimate admin work over HTTP or, more likely, shenanigans.

## Main Features
### Authentication
<img width="931" height="570" alt="image" src="https://github.com/user-attachments/assets/56f225b0-f776-41b0-8e21-2f9fd94d45f1" />
Uses Flask_Login for authentication. You can hardcode plaintext credentials or set environment variables containing an scrypt hash. Default creds: `admin:mallorca`.

### System Monitor
The Dashboard contains basic system info like CPU usage, RAM usage, disk usage, and the heaviest processes currently running. Not very useful, but helps you see the system at a glance.

### File Manager
<img width="981" height="522" alt="image" src="https://github.com/user-attachments/assets/9a0d93d6-2353-485d-97e3-73b8b8798a03" />

Lets you browse, upload, delete, and download files. Might add support for downloading full folders as zips later. For now, zip them yourself in the shell if you must.

### PTY Shell
<img width="1390" height="828" alt="image" src="https://github.com/user-attachments/assets/350ef9e9-4fa2-455d-9cdd-72e620dee1aa" />

The biggest advantage over a dumb(er) webshell is that this allocates a full PTY for you. Who doesn't hate it when you're using a webshell and don't have nano, tab completion, interactive sudo... This one's a full PTY, so you get all that and whatever else is available on the system. So that's cool. Very loud and un-stealthy since, again, it allocates a PTY.

## Deploy
You can either deploy it as-is as a script, or package it with something like PyInstaller, or compile it with Nuitka. One thing to note is that this was made for Unix based environments and is untested on Windows (likely won't work.)

### Clone Repository
```bash
git clone https://github.com/Daniel-B-Lind/kmdshell && cd kmdshell
```

### Configure
Open `kmdshell.py` and find the Config class to edit ports, base directories, credentials, and whether or not you want to enforce a reverse proxy. **You should really change SECRET_KEY**, otherwise anyone who stumbles onto your unconfigured webshell can generate a session for themselves.

The environment variables KMD_HASH and KMD_PWD can be set to hold an Scrypt hash or a plaintext password respectively, and those will be used instead of the hardcoded default if present.

### Fetch requirements
`pip -r requirements.txt`

### Run
`python3 kmdshell.py`

### (OR) Bundle
```bash
python3 -m PyInstaller --onefile --clean --strip \
--hidden-import="engineio.async_drivers.threading" \
--hidden-import="flask_socketio.cli" \
--name kmd kmdshell.py
```
`dist/kmd`

(note the hidden imports, pyinstaller doesn't pick that jank up by itself)

### (OR) Compile
```bash
python3 -m nuitka --standalone --onefile \
--include-package=engineio \
--include-package=flask_socketio \
--output-filename=kmd \
kmdshell.py
```

## Generic Disclaimer
You've heard it all before, but obviously don't use webshells (or any shells) to control systems you're not allowed to. Don't be silly, cybercrime is bad, etc., etc., whatever.
