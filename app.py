from flask import Flask, jsonify, render_template, Response, request, url_for, session, redirect, flash
import subprocess, re

app = Flask(__name__)
app.secret_key = 'haproxy'

USERNAME = "admin"
PASSWORD = "admin123"

# Path ke file konfigurasi HAProxy di dalam folder static
CONFIG_FILE_PATH = ('/etc/haproxy/haproxy.cfg')

def is_haproxy_exist():
    with open('/etc/haproxy/haproxy.cfg', 'r') as haproxy_cfg:
        content = haproxy_cfg.read()
        if "frontend " in content or "backend " in content:
            return True
    return False

def read_from_file():
    data = []
    with open(CONFIG_FILE_PATH, 'r') as f:
        content = f.read().strip()

        # Memperbarui pola regex untuk menangkap semua elemen dengan benar
        pattern = re.compile(r'frontend\s+(\S+)\s+.*?bind\s+(\S+):(\d+).*?\n\s+mode\s+(\S+).*?\n\s+default_backend\s+(\S+).*?\nbackend\s+(\S+).*?\n\s+balance\s+(\S+).*?\n\s+server\s+(\S+)\s+(\S+):(\d+)\s+check', re.DOTALL)
        matches = pattern.findall(content)

        # Format data untuk ditampilkan dalam tabel
        for match in matches:
            haproxy_name = match[0].strip()
            frontend_port = match[2].strip()
            protocol = match[3].strip()
            lb_method = match[6].strip()
            backend_server_names = match[7].strip()
            backend_server_ips = match[8].strip()
            backend_server_ports = match[9].strip()
            data.append({'haproxy_name': haproxy_name, 'frontend_port': frontend_port, 'protocol': protocol, 'lb_method': lb_method, 'backend_server_names': backend_server_names, 'backend_server_ips': backend_server_ips, 'backend_server_ports': backend_server_ports})

    return data

def save_to_file(data):
    if is_haproxy_exist():
        return {'success': False, 'message': "Konfigurasi HAProxy sudah ada. Tidak bisa menambah konfigurasi baru."}

    haproxy_name = data.get('haproxy_name')
    frontend_port = data.get('frontend_port')
    protocol = data.get('protocol')
    lb_method = data.get('lb_method')
    backend_servers = data.get('backend_servers', [])
    use_ssl = data.get('use_ssl', False)
    ssl_cert_path = data.get('ssl_cert_path', '')

    with open(CONFIG_FILE_PATH, 'a') as haproxy_cfg:
        # Frontend configuration
        haproxy_cfg.write(f"\nfrontend {haproxy_name}\n")

        # Bind and protocol configurations
        if protocol == 'http':
            if use_ssl:
                haproxy_cfg.write(f"        bind *:443 ssl crt {ssl_cert_path}\n")
                haproxy_cfg.write(f"        redirect scheme https code 301 if !{{ ssl_fc }}\n")
            else:
                haproxy_cfg.write(f"        bind *:80\n")
            haproxy_cfg.write(f"        mode http\n")
        elif protocol == 'tcp':
            if use_ssl:
                haproxy_cfg.write(f"        bind *:{frontend_port} ssl crt {ssl_cert_path}\n")
                haproxy_cfg.write(f"        redirect scheme https code 301 if !{{ ssl_fc }}\n")
            else:
                haproxy_cfg.write(f"        bind *:{frontend_port}\n")
            haproxy_cfg.write(f"        mode tcp\n")

        haproxy_cfg.write(f"        default_backend {haproxy_name}\n")

        # Backend configuration
        haproxy_cfg.write(f"\nbackend {haproxy_name}\n")
        haproxy_cfg.write(f"        balance {lb_method}\n")

        # Adding backend servers
        for backend_server_info in backend_servers:
            backend_server_name, backend_server_ip, backend_server_port = backend_server_info
            if backend_server_name and backend_server_ip and backend_server_port:
                haproxy_cfg.write(f"        server {backend_server_name} {backend_server_ip}:{backend_server_port} check\n")

        # Stats configuration
        haproxy_cfg.write(f"\nlisten stats\n")
        haproxy_cfg.write(f"        bind :9999\n")
        haproxy_cfg.write(f"        mode http\n")
        haproxy_cfg.write(f"        stats enable\n")
        haproxy_cfg.write(f"        stats hide-version\n")
        haproxy_cfg.write(f"        stats uri /stats\n")
        haproxy_cfg.write(f"        stats realm Haproxy\\ Statistics\n")
        haproxy_cfg.write(f"        stats auth admin:password\n")

    return {'success': True, 'message': "Frontend and Backend added successfully."}


def delete_to_file(haproxy_name):
    with open(CONFIG_FILE_PATH, 'r') as haproxy_cfg:
        lines = haproxy_cfg.readlines()

    new_lines = []
    inside_frontend = False
    inside_backend = False
    inside_listen_stats = False
    backend_name = None

    for line in lines:
        stripped_line = line.strip()

        # Handle frontend section
        if stripped_line.startswith(f"frontend {haproxy_name}"):
            inside_frontend = True
            continue  # Skip this line (delete it)
        
        if inside_frontend and stripped_line.startswith("default_backend"):
            backend_name = stripped_line.split(" ")[1]  # Capture the backend name to delete

        if inside_frontend and not stripped_line:
            # End of frontend block
            inside_frontend = False
            continue
        
        # Handle backend section
        if backend_name and stripped_line.startswith(f"backend {backend_name}"):
            inside_backend = True
            continue  # Skip this line (delete it)
        
        if inside_backend and not stripped_line:
            # End of backend block
            inside_backend = False
            backend_name = None  # Reset backend name after processing
            continue
        
        # Handle listen stats section
        if stripped_line.startswith("listen stats"):
            inside_listen_stats = True
            continue  # Skip this line (delete it)
        
        if inside_listen_stats and not stripped_line:
            # End of listen stats block
            inside_listen_stats = False
            continue

        # Add non-empty lines and lines outside of the deleted sections
        if not inside_frontend and not inside_backend and not inside_listen_stats:
            if stripped_line or new_lines and new_lines[-1].strip():  # Avoid adding multiple blank lines
                new_lines.append(line)

    # Write the updated configuration back to the file
    with open(CONFIG_FILE_PATH, 'w') as haproxy_cfg:
        haproxy_cfg.writelines(new_lines)

    return f"Frontend '{haproxy_name}' and its associated backend have been deleted."


def sum_haproxy():
    frontend_count = 0
    backend_count = 0
    layer7_count = 0
    layer4_count = 0
    haproxy_name = ''
    modes = set()
    inside_frontend = False

    with open(CONFIG_FILE_PATH, 'r') as haproxy_cfg:
        lines = haproxy_cfg.readlines()

        for line in lines:
            line = line.strip()

            # Detect frontend blocks
            if line.startswith('frontend '):
                frontend_count += 1
                haproxy_name = line.split()[1]  # Capture the current frontend name
                inside_frontend = True  # We are inside a frontend block

            # Detect backend blocks
            elif line.startswith('backend '):
                backend_count += 1
                haproxy_name = line.split()[1]  # Capture the current backend name
                inside_frontend = False  # We are no longer inside a frontend block

            # Check for protocol modes only inside frontend blocks
            if inside_frontend and line.startswith('mode'):
                mode = line.split()[1]
                modes.add(mode)
                if mode == 'http':
                    layer7_count += 1
                elif mode == 'tcp':
                    layer4_count += 1

    return frontend_count, backend_count, layer7_count, layer4_count, haproxy_name, modes


@app.route("/", methods=["GET", "POST"])
def index():
    if session.get('logged_in'):
        return '<script>alert("Akses dilarang"); window.location.href = "/home";</script>'

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == USERNAME and password == PASSWORD:

            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for("home"))  

        else:
            flash("Invalid username or password", "danger") 

    return render_template('index.html')

@app.route("/home")
def home():
    if not session.get('logged_in'):
        return '<script>alert("Harus login dulu"); window.location.href = "/";</script>'

    frontend_count, backend_count, layer7_count, layer4_count, haproxy_name, modes  = sum_haproxy()
    haproxy_exists = is_haproxy_exist()

    return render_template('home.html', frontend_count=frontend_count, backend_count=backend_count, layer7_count=layer7_count, layer4_count=layer4_count, haproxy_name=haproxy_name, modes=modes, haproxy_exists=haproxy_exists)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route("/add", methods=['GET', 'POST'])
def add():
    if not session.get('logged_in'):
        return '<script>alert("Harus login dulu"); window.location.href = "/";</script>'

    if request.method == 'POST':
        data = {
            'haproxy_name': request.form['haproxy_name'],
            'frontend_port': request.form['frontend_port'],
            'lb_method': request.form['lb_method'],
            'protocol': request.form['protocol'],
            'use_ssl': 'ssl_checkbox' in request.form,
            'ssl_cert_path': request.form.get('ssl_cert_path', ''),
            'backend_servers': list(zip(
                request.form.getlist('backend_server_names'),
                request.form.getlist('backend_server_ips'),
                request.form.getlist('backend_server_ports')
            ))
        }

        # Save configuration to file
        result = save_to_file(data)

        if result['success']:
            if 'save_reload_create' in request.form:
                # Run haproxy -c -V -f to check the configuration
                check_result = subprocess.run(['haproxy', '-c', '-V', '-f', CONFIG_FILE_PATH], capture_output=True, text=True)
                check_output = check_result.stdout

                # Check if there was an error, and if so, append it to the output
                if check_result.returncode != 0:
                    error_message = check_result.stderr
                    check_output += f"\n\nError occurred:\n{error_message}"
                else:
                    # If no error, run haproxy -D -f to reload HAProxy
                    reload_result = subprocess.run(['systemctl', 'restart', 'haproxy', CONFIG_FILE_PATH], capture_output=True, text=True)
                    check_output += f"\n\nHAProxy Restart Output:\n{reload_result.stdout}"

            return redirect(url_for('home'))
        else:
            return '<script>alert("Konfigurasi HAProxy sudah ada. Tidak bisa menambah konfigurasi baru."); window.location.href = "/home";</script>'

    return render_template('HAProxy/add.html')


@app.route("/edit/<string:haproxy_name>", methods=['GET', 'POST'])
def edit(haproxy_name):
    if not session.get('logged_in'):
        return '<script>alert("Harus login dulu"); window.location.href = "/";</script>'
        
    data = read_from_file()
    item = next((d for d in data if d['haproxy_name'] == haproxy_name), None)

    if request.method == 'POST':
        if item:
            # Step 1: Get data from the form
            item.update({
                'haproxy_name': request.form['haproxy_name'],
                'frontend_port': request.form['frontend_port'],
                'protocol': request.form['protocol'],
                'lb_method': request.form['lb_method'],
                'use_ssl': 'ssl_checkbox' in request.form,
                'ssl_cert_path': request.form.get('ssl_cert_path', ''),
                'backend_servers': list(zip(
                request.form.getlist('backend_server_names'),
                request.form.getlist('backend_server_ips'),
                request.form.getlist('backend_server_ports')
            ))
            })

            # Step 2: Delete the old configuration
            delete_to_file(haproxy_name)

            # Step 3: Save the new configuration to the file
            save_to_file(item)

            if 'save_reload_update' in request.form:
                # Validate the HAProxy configuration
                check_result = subprocess.run(['haproxy', '-c', '-V', '-f', CONFIG_FILE_PATH], capture_output=True, text=True)
                check_output = check_result.stdout

                if check_result.returncode != 0:
                    error_message = check_result.stderr
                    check_output += f"\n\nError occurred:\n{error_message}"
                else:
                    # Reload HAProxy if validation succeeds
                    reload_result = subprocess.run(['systemctl', 'restart', 'haproxy'], capture_output=True, text=True)
                    check_output += f"\n\nHAProxy Restart Output:\n{reload_result.stdout}"

            return redirect(url_for('home'))

    return render_template('HAProxy/edit.html', **item)


@app.route("/delete", methods=['POST'])
def delete():
    if request.method == 'POST':
        haproxy_name = request.form['haproxy_name']

        delete_to_file(haproxy_name)  # Use custom function to save the updated data

        # Check if the save_reload_delete button was pressed
        if 'save_reload_delete' in request.form:
            # Validate HAProxy configuration
            check_result = subprocess.run(['haproxy', '-c', '-f', CONFIG_FILE_PATH], capture_output=True, text=True)
            check_output = check_result.stdout

            if check_result.returncode != 0:
                error_message = check_result.stderr
                check_output += f"\n\nError occurred:\n{error_message}"
                flash('Configuration validation failed. See details below.', 'error')
                return render_template('home.html', check_output=check_output)

            # Restart HAProxy if validation succeeds
            reload_result = subprocess.run(['systemctl', 'restart', 'haproxy'], capture_output=True, text=True)
            check_output += f"\n\nHAProxy Restart Output:\n{reload_result.stdout}"

            flash('Configuration deleted and HAProxy has been restarted!', 'success')
            return redirect(url_for('home'))

    return render_template('home.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
