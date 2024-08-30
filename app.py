from flask import Flask, jsonify, render_template, Response, request, url_for, session, redirect, flash
from werkzeug.security import generate_password_hash, check_password_hash
import subprocess, re, os

app = Flask(__name__)
app.secret_key = 'haproxy'

users = {
    'admin': generate_password_hash('admin123')
}

# Path ke file konfigurasi HAProxy di dalam folder static
CONFIG_FILE_PATH = ('/etc/haproxy/haproxy.cfg')
SSL_FILE_PATH = ('/etc/haproxy-dashboard/ssl/key.pem')
DOMAIN_FILE_PATH = ('/etc/haproxy-dashboard/ssl/domain.txt')


def certificate(content):
    with open(SSL_FILE_PATH, 'w') as file:
        file.write(content)
    return f"{SSL_FILE_PATH}"

def domain(domain_content):
    with open(DOMAIN_FILE_PATH, 'w') as file:
        file.write(domain_content)
    return f"{DOMAIN_FILE_PATH}"


def is_haproxy_exist():
    with open(CONFIG_FILE_PATH, 'r') as haproxy_cfg:
        content = haproxy_cfg.read()
        if "frontend " in content or "backend " in content:
            return True
    return False

def is_domain_exist():
    if os.path.exists(DOMAIN_FILE_PATH):
        with open(DOMAIN_FILE_PATH, 'r') as domain_file:
            content = domain_file.read()
        return content  
    else:
        return None  



def read_from_file():
    data = []
    with open(CONFIG_FILE_PATH, 'r') as f:
        content = f.read().strip()

        # Pola regex untuk frontend dan backend
        pattern1 = re.compile(r'frontend\s+(\S+)\s+.*?bind\s+(\S+):(\d+).*?\n\s+mode\s+(\S+).*?\n\s+default_backend\s+(\S+).*?\nbackend\s+(\S+).*?\n\s+balance\s+(\S+)', re.DOTALL)
        frontend_matches = pattern1.findall(content)

        # Pola regex untuk backend dengan weight
        pattern2 = re.compile(r'server\s+(\w+)\s+([\d.]+:\d+)\s+weight\s+(\d+)\s+check', re.DOTALL)
        weight_matches = pattern2.findall(content)

        # Pola regex untuk backend tanpa weight
        pattern3 = re.compile(r'server\s+(\w+)\s+([\d.]+:\d+)\s+check', re.DOTALL)
        server_matches = pattern3.findall(content)

        # print("frontend_matches:", frontend_matches)
        # print("weight_matches:", weight_matches)
        # print("server_matches:", server_matches)
        backend_servers = []
        
        for match in frontend_matches:
            haproxy_name = match[0].strip()
            frontend_port = match[2].strip()
            protocol = match[3].strip()
            lb_method = match[6].strip()

            data.append({
                'haproxy_name': haproxy_name, 
                'frontend_port': frontend_port, 
                'protocol': protocol, 
                'lb_method': lb_method, 
                'count_server': len(backend_servers)
            })
        
        if lb_method == 'roundrobin':
            for weight_match in weight_matches:
                backend_servers.append({
                    'name': weight_match[0].strip(),
                    'ip': weight_match[1].split(':')[0].strip(),
                    'port': weight_match[1].split(':')[1].strip(),
                    'weight': weight_match[2].strip()
                })
        else:
            for server_match in server_matches:
                backend_servers.append({
                    'name': server_match[0].strip(),
                    'ip': server_match[1].split(':')[0].strip(),
                    'port': server_match[1].split(':')[1].strip(),
                })

        print(backend_servers)
        data[0]['count_server'] = len(backend_servers)
        data[0]['backend_servers'] = zip(backend_servers, range(1, len(backend_servers) +1 ))
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
    domain_name = data.get('domain_name', '')

    # Write SSL certificate to file if provided
    if use_ssl and ssl_cert_path:
        with open(SSL_FILE_PATH, 'w') as cert_file:
            cert_file.write(ssl_cert_path)
        with open(DOMAIN_FILE_PATH, 'w') as domain_file:
            domain_file.write(domain_name)

    # Write HAProxy configuration
    with open(CONFIG_FILE_PATH, 'a') as haproxy_cfg:
        # Frontend configuration
        haproxy_cfg.write(f"\nfrontend {haproxy_name}\n")

        # Bind and protocol configurations
        if protocol == 'tcp':
            if use_ssl:
                haproxy_cfg.write(f"        bind *:{frontend_port} ssl crt /etc/haproxy-dashboard/ssl/key.pem\n")
                haproxy_cfg.write(f"        redirect scheme https code 301 if !{{ ssl_fc }}\n")
            else:
                haproxy_cfg.write(f"        bind *:{frontend_port}\n")
            haproxy_cfg.write(f"        mode tcp\n")
        elif protocol == 'http':
            if use_ssl:
                haproxy_cfg.write(f"        bind *:443 ssl crt /etc/haproxy-dashboard/ssl/key.pem\n")
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

        # Stats configuration
        haproxy_cfg.write(f"\nlisten stats\n")
        haproxy_cfg.write(f"        bind :9999\n")
        haproxy_cfg.write(f"        mode http\n")
        haproxy_cfg.write(f"        stats enable\n")
        haproxy_cfg.write(f"        stats hide-version\n")
        haproxy_cfg.write(f"        stats uri /stats\n")
        haproxy_cfg.write(f"        stats realm Haproxy\\ Statistics\n")

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


def haproxy_info():
    layer7_count = 0
    layer4_count = 0
    haproxy_name = ''
    frontend_port = ''
    lb_method = ''
    backend_servers = []
    modes = set()
    inside_frontend = False
    inside_backend = False

    with open(CONFIG_FILE_PATH, 'r') as haproxy_cfg:
        lines = haproxy_cfg.readlines()

        for line in lines:
            line = line.strip()

            # Detect frontend blocks
            if line.startswith('frontend '):
                haproxy_name = line.split()[1]  # Capture the current frontend name
                inside_frontend = True  # We are inside a frontend block
                inside_backend = False  # We are inside a frontend block

            # Detect backend blocks
            elif line.startswith('backend '):
                haproxy_name = line.split()[1]  # Capture the current backend name
                inside_frontend = False  # We are no longer inside a frontend block
                inside_backend = True  # We are no longer inside a frontend block
            
            if inside_frontend and line.startswith('bind '):
                bind_parts = line.split()
                if ':' in bind_parts[1]:  # Assuming bind format is "bind *:80"
                    frontend_port = bind_parts[1].split(':')[1]
            
            if inside_backend and line.startswith('balance '):
                lb_method = line.split()[1]
            
            if inside_backend and line.startswith('server '):
                parts = line.split()
                server_name = parts[1]  # Extract server name
                server_ip = parts[2].split(':')[0]  # Extract server IP (before the colon)
                backend_servers.append((server_name, server_ip))

            # Check for protocol modes only inside frontend blocks
            if inside_frontend and line.startswith('mode'):
                mode = line.split()[1]
                modes.add(mode)
                if mode == 'http':
                    layer7_count += 1
                elif mode == 'tcp':
                    layer4_count += 1

    return frontend_port, layer7_count, layer4_count, haproxy_name, modes, lb_method, backend_servers


@app.route("/", methods=["GET", "POST"])
def index():
    if session.get('logged_in'):
        return '<script>alert("Akses dilarang"); window.location.href = "/home";</script>'

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username in users and check_password_hash(users[username], password):
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

    frontend_port, layer7_count, layer4_count, haproxy_name, modes, lb_method, backend_servers = haproxy_info()
    haproxy_exists = is_haproxy_exist()
    domain_exists = is_domain_exist()

    return render_template('home.html', frontend_port=frontend_port, layer7_count=layer7_count, layer4_count=layer4_count, haproxy_name=haproxy_name, modes=modes, lb_method=lb_method, backend_servers=backend_servers, haproxy_exists=haproxy_exists, domain_exists=domain_exists)

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
    
    ssl_cert_content = ''
    domain_name_content = ''

    data = read_from_file()
    item = next((d for d in data if d['haproxy_name'] == haproxy_name), None)

    if request.method == 'POST':
        if item:
            # Step 1: Get data from the form
            ssl_cert_content = request.form.get('ssl_cert_path', '')
            domain_name_content = request.form.get('domain_name', '')
            certificate(ssl_cert_content)
            domain(domain_name_content)
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

    ssl_cert_content = ''
    if os.path.exists(SSL_FILE_PATH):
        with open(SSL_FILE_PATH, 'r') as file:
            ssl_cert_content = file.read()
    
    domain_name_content = ''
    if os.path.exists(DOMAIN_FILE_PATH):
        with open(DOMAIN_FILE_PATH, 'r') as file:
            domain_name_content = file.read()
            
    return render_template('HAProxy/edit.html', **item, ssl_cert_path=ssl_cert_content, domain_name=domain_name_content)


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


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_password():
    if not session.get('logged_in'):
        return '<script>alert("Harus login dulu"); window.location.href = "/";</script>'
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        password_confirmation = request.form.get('password_confirmation')
        username = session.get('username')

        if new_password == password_confirmation:
            users[username] = generate_password_hash(new_password)
            session.clear()
            return '<script>alert("Password berhasil direset"); window.location.href = "/";</script>'
        else:
            return '<script>alert("Password gagal direset"); window.location.href = "/home";</script>'
    
    return render_template('reset_password.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
