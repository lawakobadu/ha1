from flask import Flask, jsonify, render_template, Response, request, url_for, session, redirect, flash, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import subprocess, re, os, jwt, datetime, json
from functools import wraps


app = Flask(__name__)
app.secret_key = 'f7d3814dd7f44e6ab8ff23c98a92c7fc'


# Path ke file konfigurasi HAProxy di dalam folder static
CONFIG_FILE_PATH = ('/etc/haproxy/haproxy.cfg')
SSL_FILE_PATH = '/etc/haproxy-dashboard/ssl/key'
DOMAIN_FILE_PATH = '/etc/haproxy-dashboard/ssl/domain'
USER_FILE_PATH = ('/etc/haproxy-dashboard/admin/user.json')

# Ensure both directories exist
for directory in [SSL_FILE_PATH, DOMAIN_FILE_PATH]:
    if not os.path.exists(directory):
        os.makedirs(directory)


def certificate(file_name, content):
    if not os.path.exists(SSL_FILE_PATH):
        os.makedirs(SSL_FILE_PATH)
    full_file_path = os.path.join(SSL_FILE_PATH, file_name)
    with open(full_file_path, 'w') as file:
        file.write(content)
    return f"{full_file_path}.pem"


def domain(file_name, domain_content):
    if not os.path.exists(DOMAIN_FILE_PATH):
        os.makedirs(DOMAIN_FILE_PATH)
    full_file_path = os.path.join(DOMAIN_FILE_PATH, file_name)
    with open(full_file_path, 'w') as file:
        file.write(domain_content)
    return f"{full_file_path}.txt"


def is_user_exist():
    with open(USER_FILE_PATH, 'r') as user:
        return json.load(user)


def save_users(users):
    with open(USER_FILE_PATH, 'w') as f:
        json.dump(users, f, indent=4)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'error': 'Token is missing!'}), 403
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired!'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token is invalid!'}), 403
        return f(*args, **kwargs)
    return decorated


def is_haproxy_exist():
    with open(CONFIG_FILE_PATH, 'r') as haproxy_cfg:
        content = haproxy_cfg.read()
        if "frontend " in content or "backend " in content:
            return True
    return False


# def get_all_domains(haproxy_name):
#     data = []
#     for domain_file in os.listdir(DOMAIN_FILE_PATH):
#         if domain_file.endswith('.txt'):
#             file_path = os.path.join(DOMAIN_FILE_PATH, domain_file)
#             with open(file_path, 'r') as file:
#                 lines = file.readlines()
#                 for line in lines:
#                     if line.startswith('haproxy_name'):
#                         name_in_file = line.split(' ')[1].strip()  # Ambil nama haproxy
#                         return name_in_file
#     return None


def sanitize_filename(domain_name):
    # Bersihkan karakter yang tidak diizinkan dalam nama file
    return re.sub(r'[^\w\-_\.]', '_', domain_name)


def read_from_file(haproxy_names):
    data = []
    with open(CONFIG_FILE_PATH, 'r') as f:
        content = f.read().strip()

        # Pola regex untuk frontend
        pattern_frontend = re.compile(r'frontend\s+(\S+)\s+.*?bind\s+(\S+):(\d+).*?\n\s+mode\s+(\S+).*?\n\s+default_backend\s+(\S+)', re.DOTALL)
        frontend_matches = pattern_frontend.findall(content)

        # Pola regex untuk backend
        pattern_backend = re.compile(r'backend\s+(\S+)\s+balance\s+(\S+)(.*?)(?=\nfrontend|\Z)', re.DOTALL)
        backend_matches = pattern_backend.findall(content)

        # Memetakan backend ke server-servernya
        pattern_backend_servers_weight = re.compile(r'server\s+(\w+)\s+([\d.]+:\d+)\s+weight\s+(\d+)\s+check')
        pattern_backend_servers_no_weight = re.compile(r'server\s+(\w+)\s+([\d.]+:\d+)\s+check')

        # print("frontend_matches:", frontend_matches)
        # print("backend_matches:", backend_matches)

        for match in frontend_matches:
            haproxy_name = match[0].strip()
            if haproxy_name == haproxy_names:
                frontend_port = match[2].strip()
                protocol = match[3].strip()
                backend_name = match[4].strip()

                # Cari backend yang sesuai dengan default_backend dari frontend
                backend_data = next(
                    (b for b in backend_matches if b[0] == backend_name), None
                )

                if backend_data:
                    lb_method = backend_data[1].strip()
                    backend_servers_block = backend_data[2].strip()

                    # Temukan server-server dalam backend
                    backend_servers = []
                    
                    if lb_method == 'roundrobin':
                        # Jika roundrobin, server-server dengan weight
                        server_matches = pattern_backend_servers_weight.findall(backend_servers_block)
                        for server in server_matches:
                            backend_servers.append({
                                'name': server[0].strip(),
                                'ip': server[1].split(':')[0].strip(),
                                'port': server[1].split(':')[1].strip(),
                                'weight': server[2].strip()
                            })
                    else:
                        # Jika bukan roundrobin, ambil server tanpa weight
                        server_matches = pattern_backend_servers_no_weight.findall(backend_servers_block)
                        for server in server_matches:
                            backend_servers.append({
                                'name': server[0].strip(),
                                'ip': server[1].split(':')[0].strip(),
                                'port': server[1].split(':')[1].strip(),
                            })

                    # Append data frontend dengan backend_servers
                    data.append({
                        'haproxy_name': haproxy_name, 
                        'frontend_port': frontend_port, 
                        'protocol': protocol, 
                        'lb_method': lb_method, 
                        'count_server': len(backend_servers),
                        'backend_servers': list(zip(backend_servers, range(1, len(backend_servers) + 1)))
                    })

                    # print(f"Data for {haproxy_name}: {data[-1]}")

    return data


def save_to_file(data):
    haproxy_name = data.get('haproxy_name')
    frontend_port = data.get('frontend_port')
    protocol = data.get('protocol')
    lb_method = data.get('lb_method')
    backend_servers = data.get('backend_servers', [])
    use_ssl = data.get('use_ssl', '')
    ssl_cert_path = data.get('ssl_cert_path', '')
    domain_name = data.get('domain_name', '')

    # Write SSL certificate to file if provided
    if use_ssl and ssl_cert_path:
        cert_file_name = f"{haproxy_name}.pem"
        certificate(cert_file_name, ssl_cert_path)

        file_domain_path = os.path.join(DOMAIN_FILE_PATH, f"{sanitize_filename(haproxy_name)}.txt")

        with open(file_domain_path, 'a') as domain_file:
            domain_file.write(domain_name)

    # Write HAProxy configuration
    with open(CONFIG_FILE_PATH, 'a') as haproxy_cfg:
        # Read current configuration to check for 'listen stats'
        with open(CONFIG_FILE_PATH, 'r') as haproxy_cfg_read:
            existing_config = haproxy_cfg_read.read()

        # Stats configuration
        if 'listen stats' not in existing_config:
            haproxy_cfg.write(f"\nlisten stats\n")
            haproxy_cfg.write(f"        bind :9999\n")
            haproxy_cfg.write(f"        mode http\n")
            haproxy_cfg.write(f"        stats enable\n")
            haproxy_cfg.write(f"        stats hide-version\n")
            haproxy_cfg.write(f"        stats uri /stats\n")
            haproxy_cfg.write(f"        stats realm Haproxy\\ Statistics\n")
            
        # Frontend configuration
        haproxy_cfg.write(f"\nfrontend {haproxy_name}\n")

        # Bind and protocol configurations
        if protocol == 'tcp':
            if use_ssl:
                haproxy_cfg.write(f"        bind *:{frontend_port} ssl crt /etc/haproxy-dashboard/ssl/key/{haproxy_name}.pem\n")
                haproxy_cfg.write(f"        redirect scheme https code 301 if !{{ ssl_fc }}\n")
            else:
                haproxy_cfg.write(f"        bind *:{frontend_port}\n")
            haproxy_cfg.write(f"        mode tcp\n")
        elif protocol == 'http':
            if use_ssl:
                haproxy_cfg.write(f"        bind *:443 ssl crt /etc/haproxy-dashboard/ssl/key/{haproxy_name}.pem\n")
                haproxy_cfg.write(f"        redirect scheme https code 301 if !{{ ssl_fc }}\n")
            else:
                haproxy_cfg.write(f"        bind *:80\n")
            haproxy_cfg.write(f"        mode http\n")

        haproxy_cfg.write(f"        default_backend {haproxy_name}\n")

        # Backend configuration
        haproxy_cfg.write(f"\nbackend {haproxy_name}\n")
        haproxy_cfg.write(f"        balance {lb_method}\n")

        # Adding backend servers
        if lb_method == 'roundrobin':
            for backend_server_info in backend_servers:
                backend_server_name, backend_server_ip, backend_server_port, backend_server_weight = backend_server_info
                if backend_server_name and backend_server_ip and backend_server_port and backend_server_weight:
                    haproxy_cfg.write(f"        server {backend_server_name} {backend_server_ip}:{backend_server_port} weight {backend_server_weight} check\n")
        else:
            for backend_server_info in backend_servers:
                backend_server_name, backend_server_ip, backend_server_port = backend_server_info
                if backend_server_name and backend_server_ip and backend_server_port:
                    haproxy_cfg.write(f"        server {backend_server_name} {backend_server_ip}:{backend_server_port} check\n")

    return {'success': True, 'message': "Frontend and Backend added successfully."}


def delete_conf(haproxy_name):
    with open(CONFIG_FILE_PATH, 'r') as haproxy_cfg:
        lines = haproxy_cfg.readlines()

    new_lines = []
    inside_frontend = False
    inside_backend = False
    inside_listen_stats = False
    backend_name = None
    haproxy_count = 0  # Counter to check remaining HAProxy frontends

    # First pass: Remove frontend and backend sections related to haproxy_name
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
        
        # Count remaining HAProxy frontends
        if stripped_line.startswith("frontend"):
            haproxy_count += 1  # Count all remaining frontends except the one being deleted

        # Add non-empty lines and lines outside of the deleted sections
        if not inside_frontend and not inside_backend:
            if stripped_line or (new_lines and new_lines[-1].strip()):  # Avoid adding multiple blank lines
                new_lines.append(line)

    # Second pass: Remove listen stats section if only one haproxy_name is left
    if haproxy_count == 0:
        final_lines = []
        inside_listen_stats = False
        for line in new_lines:
            stripped_line = line.strip()
            
            if stripped_line.startswith("listen stats"):
                inside_listen_stats = True
                continue  # Skip this line (delete it)
            
            if inside_listen_stats and not stripped_line:
                # End of listen stats block
                inside_listen_stats = False
                continue

            # Add non-empty lines and lines outside of the deleted sections
            if not inside_listen_stats:
                final_lines.append(line)
        
        new_lines = final_lines

    # Write the updated configuration back to the file
    with open(CONFIG_FILE_PATH, 'w') as haproxy_cfg:
        haproxy_cfg.writelines(new_lines)

    return f"Frontend '{haproxy_name}' and its associated backend have been deleted."


def haproxy_info():
    haproxy_data = []
    layer7_count = 0
    layer4_count = 0
    frontend_port = ''
    lb_method = ''
    backend_servers = []
    modes = set()
    haproxy_name = ''
    inside_frontend = False
    inside_backend = False

    with open(CONFIG_FILE_PATH, 'r') as haproxy_cfg:
        lines = haproxy_cfg.readlines()

        for line in lines:
            line = line.strip()

            # Detect frontend blocks
            if line.startswith('frontend '):
                # Jika sebelumnya sudah ada data frontend yang dikumpulkan, simpan dulu
                if haproxy_name:
                    haproxy_data.append({
                        'haproxy_name': haproxy_name,
                        'frontend_port': frontend_port,
                        'lb_method': lb_method,
                        'backend_servers': backend_servers,
                        'modes': modes
                    })

                # Reset variabel untuk frontend baru
                haproxy_name = line.split()[1]
                frontend_port = ''
                lb_method = ''
                backend_servers = []
                modes = set()
                inside_frontend = True
                inside_backend = False

            # Detect backend blocks
            elif line.startswith('backend '):
                inside_frontend = False
                inside_backend = True

            # Handle frontend settings
            if inside_frontend:
                if line.startswith('bind '):
                    bind_parts = line.split()
                    if ':' in bind_parts[1]:  # Assuming bind format is "bind *:80"
                        frontend_port = bind_parts[1].split(':')[1]

                if line.startswith('mode'):
                    mode = line.split()[1]
                    modes.add(mode)
                    if mode == 'http':
                        layer7_count += 1
                    elif mode == 'tcp':
                        layer4_count += 1

            # Handle backend settings
            if inside_backend:
                if line.startswith('balance '):
                    lb_method = line.split()[1]

                if line.startswith('server '):
                    parts = line.split()
                    server_name = parts[1]
                    server_ip = parts[2].split(':')[0]
                    backend_servers.append((server_name, server_ip))

        # Pastikan data terakhir dimasukkan ke dalam list
        if haproxy_name:
            haproxy_data.append({
                'haproxy_name': haproxy_name,
                'frontend_port': frontend_port,
                'lb_method': lb_method,
                'backend_servers': backend_servers,
                'modes': modes
            })

    return haproxy_data, layer7_count, layer4_count


@app.route("/", methods=["GET", "POST"])
def index():
    if session.get('logged_in'):
        return '<script>alert("Akses dilarang"); window.location.href = "/home";</script>'

    is_user = is_user_exist()

    if request.method == "POST":
        data = request.get_json()

        if not data or 'username' not in data or 'password' not in data:
            return make_response('Missing credentials', 400)

        username = data['username']
        password = data['password']

        # if username in is_user and is_user[username]['password'] == password:
        if username in is_user and check_password_hash(is_user[username]['password'], password):
            session['logged_in'] = True
            session['username'] = username
            token = jwt.encode({
                'user': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=60)
            },
            app.config['SECRET_KEY'], algorithm="HS256")

            return jsonify({
                'message': True,
                'token': token
            })
        else:
            return jsonify({'message': False}), 401

    return render_template('index.html')


def get_all_domains(haproxy_name):
    domain_file_path = os.path.join(DOMAIN_FILE_PATH, f"{haproxy_name}.txt")
    if os.path.exists(domain_file_path):
        with open(domain_file_path, 'r') as file:
            content = file.read()
        return content
    else:
        return None


@app.route("/home", methods=['GET', 'POST'])
def home():
    if not session.get('logged_in'):
        return '<script>alert("Harus login dulu"); window.location.href = "/";</script>'
    
    haproxy_name = request.args.get('haproxy_name')
    file_name = request.args.get('file_name')
    
    haproxy_data, layer7_count, layer4_count = haproxy_info()
    domains = get_all_domains(haproxy_name)
    print(f"list domain : {domains}")
    haproxy_exists = is_haproxy_exist()

    return render_template(
        'home.html', 
        haproxy_data=haproxy_data, 
        haproxy_exists=haproxy_exists, 
        domains=domains,
        layer7_count=layer7_count,
        layer4_count=layer4_count,
        file_name=file_name
    )


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route("/add", methods=['GET', 'POST'])
def add():
    if not session.get('logged_in'):
        return '<script>alert("Harus login dulu"); window.location.href = "/";</script>'

    if request.method == 'POST':
        lb_method = request.form['lb_method']

        data = {
            'haproxy_name': request.form['haproxy_name'],
            'frontend_port': request.form['frontend_port'],
            'lb_method': lb_method,
            'protocol': request.form['protocol'],
            'use_ssl': 'ssl_checkbox' in request.form,
            'ssl_cert_path': request.form.get('ssl_cert_path', ''),
            'domain_name': request.form.get('domain_name', '')
        }

        if lb_method == 'roundrobin':
            # Include weights for roundrobin
            data['backend_servers'] = list(zip(
                request.form.getlist('backend_server_names'),
                request.form.getlist('backend_server_ips'),
                request.form.getlist('backend_server_ports'),
                request.form.getlist('backend_server_weights')
        ))
        else:
            # For other methods, omit weights
            data['backend_servers'] = list(zip(
                request.form.getlist('backend_server_names'),
                request.form.getlist('backend_server_ips'),
                request.form.getlist('backend_server_ports')
        ))
        
        # Save configuration to file
        save_to_file(data)

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

    return render_template('HAProxy/add.html')


@app.route("/edit/<haproxy_name>", methods=['GET', 'POST'])
def edit(haproxy_name):
    if not session.get('logged_in'):
        return '<script>alert("Harus login dulu"); window.location.href = "/";</script>'
    
    ssl_cert_content = ''
    domain_name_content = ''

    data = read_from_file(haproxy_name)
    item = next((d for d in data if d['haproxy_name'] == haproxy_name), None)

    if request.method == 'POST':
        if item:
            # Step 1: Get data from the form
            ssl_cert_content = request.form.get('ssl_cert_path', '')
            domain_name_content = request.form.get('domain_name', '')
            if ssl_cert_content:
                certificate(f"{haproxy_name}.pem", ssl_cert_content)
            if domain_name_content:
                domain(f"{haproxy_name}.txt", domain_name_content)
                
            item.update({
                'haproxy_name': request.form['haproxy_name'],
                'frontend_port': request.form['frontend_port'],
                'protocol': request.form['protocol'],
                'use_ssl': 'ssl_checkbox' in request.form,
                'ssl_cert_path': ssl_cert_content,
                'domain_name': domain_name_content,
                'lb_method': request.form['lb_method']
            })

            if item['lb_method'] == 'roundrobin':
                item['backend_servers'] = list(zip(
                request.form.getlist('backend_server_names'),
                request.form.getlist('backend_server_ips'),
                request.form.getlist('backend_server_ports'),
                request.form.getlist('backend_server_weights')
                ))
            else:
                item['backend_servers'] = list(zip(
                request.form.getlist('backend_server_names'),
                request.form.getlist('backend_server_ips'),
                request.form.getlist('backend_server_ports')
            ))
            
            # Step 2: Delete the old configuration
            delete_conf(haproxy_name)

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

    ssl_cert_file = os.path.join(SSL_FILE_PATH, f"{haproxy_name}.pem")
    domain_file = os.path.join(DOMAIN_FILE_PATH, f"{haproxy_name}.txt")

    if os.path.isfile(ssl_cert_file):
        with open(ssl_cert_file, 'r') as file:
            ssl_cert_content = file.read()
    
    if os.path.isfile(domain_file):
        with open(domain_file, 'r') as file:
            domain_name_content = file.read()
            
    return render_template('HAProxy/edit.html', **item, ssl_cert_path=ssl_cert_content, domain_name=domain_name_content)


@app.route("/delete/<haproxy_name>/<file_name>", methods=['POST'])
def delete(haproxy_name, file_name):
    # print(f'Deleting HAProxy: {haproxy_name}, File: {file_name}')
    delete_conf(haproxy_name)

    key_file = os.path.join(SSL_FILE_PATH, file_name + ".pem")
    domain_file = os.path.join(DOMAIN_FILE_PATH, file_name + ".txt")
    # print(f'Key file: {key_file}, Domain file: {domain_file}')

    if os.path.exists(key_file):
        os.remove(key_file)
    else:
        flash(f'PEM file "{file_name}.pem" not found!', 'error')
    
    if os.path.exists(domain_file):
        os.remove(domain_file)
    else:
        flash(f'TXT file "{file_name}.txt" not found!', 'error')

    if not os.path.exists(key_file) and not os.path.exists(domain_file):
        flash(f'Files "{file_name}.txt" and "{file_name}.pem" successfully deleted!', 'success')

    # Check if the save_reload_delete button was pressed
    if 'save_reload_delete' in request.form:
        # Validate HAProxy configuration
        check_result = subprocess.run(['haproxy', '-c', '-f', CONFIG_FILE_PATH], capture_output=True, text=True)
        check_output = check_result.stdout

        if check_result.returncode != 0:
            error_message = check_result.stderr
            check_output += f"\n\nError occurred:\n{error_message}"
            flash('Configuration validation failed. See details below.', 'error')
            return redirect(url_for('home'))

        # Restart HAProxy if validation succeeds
        reload_result = subprocess.run(['systemctl', 'restart', 'haproxy'], capture_output=True, text=True)
        check_output += f"\n\nHAProxy Restart Output:\n{reload_result.stdout}"

        flash('Configuration deleted and HAProxy has been restarted!', 'success')
        return redirect(url_for('home'))

    return render_template('home.html')


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_password():
    if not session.get('logged_in'):
        return '<script>alert("Harus login dulu"); window.location.href = "/";</script>'
    
    is_user = is_user_exist()
    username = session.get('username')

    if username not in is_user:
        return '<script>alert("User tidak ditemukan"); window.location.href = "/";</script>'

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        password_confirmation = request.form.get('password_confirmation')

        if not new_password or not password_confirmation:
            return '<script>alert("Harap mengisi semua kolom password"); window.location.href = "/reset_password";</script>'

        if new_password == password_confirmation:
            hashed_password = generate_password_hash(new_password)
            is_user[username]['password'] = hashed_password
            save_users(is_user)
            session.clear()
            return '<script>alert("Password berhasil direset"); window.location.href = "/";</script>'
        else:
            return '<script>alert("Password tidak cocok"); window.location.href = "/reset_password";</script>'
    
    return render_template('reset_password.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
