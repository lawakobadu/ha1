from flask import Flask, jsonify, render_template, Response, request, url_for, session, redirect, flash, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import subprocess, re, os, jwt, datetime, json, csv, requests
from functools import wraps
from requests.exceptions import ConnectionError
from OpenSSL import SSL
import configparser
import ssl
from datetime import timedelta
import secrets, string


app = Flask(__name__)
app.secret_key = 'f7d3814dd7f44e6ab8ff23c98a92c7fc'
# app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=300)


# Path ke file konfigurasi HAProxy di dalam folder static
CONFIG_FILE_PATH = ('/etc/haproxy/haproxy.cfg')
SSL_FILE_PATH = ('/etc/haproxy-dashboard/ssl/')
USER_FILE_PATH = ('/etc/haproxy-dashboard/admin/user.json')


def certificate(file_name, content):
    if not os.path.exists(SSL_FILE_PATH):
        os.makedirs(SSL_FILE_PATH)
    full_file_path = os.path.join(SSL_FILE_PATH, file_name)
    with open(full_file_path, 'w') as file:
        file.write(content)
    return f"{full_file_path}.pem"


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


def read_from_file(backend_name):
    data = []
    with open(CONFIG_FILE_PATH, 'r') as f:
        content = f.read().strip()

        # Pola regex untuk frontend
        pattern_frontend = re.compile(r'frontend\s+(\S+)\s*.*?bind\s+\S+:(\d+)(?:\s+ssl\s+crt\s+\S+)?\s*.*?mode\s+(\S+).*?(use_backend\s+\S+.*?)*(?=frontend|\Z)', re.DOTALL)
        frontend_matches = pattern_frontend.findall(content)

        # Pola regex untuk backend
        pattern_backend = re.compile(r'backend\s+(\S+)\s+balance\s+(\S+)(.*?)(?=\nfrontend|\nbackend|\Z)', re.DOTALL)
        backend_matches = pattern_backend.findall(content)

        # Pola regex untuk server dengan dan tanpa weight
        pattern_backend_servers_weight = re.compile(r'server\s+(\w+)\s+([\d.]+:\d+)\s+weight\s+(\d+)\s+check')
        pattern_backend_servers_no_weight = re.compile(r'server\s+(\w+)\s+([\d.]+:\d+)\s+check')

        # Proses dan simpan hasil sesuai dengan backend_name
        for backend in backend_matches:
            current_backend_name = backend[0]
            lb_method = backend[1]
            backend_servers_block = backend[2]

            if current_backend_name == backend_name:
                backend_servers = []
                
                # Ambil server sesuai metode load balancing
                if lb_method == 'roundrobin':
                    server_matches = pattern_backend_servers_weight.findall(backend_servers_block)
                    for server in server_matches:
                        backend_servers.append({
                            'name': server[0].strip(),
                            'ip': server[1].split(':')[0].strip(),
                            'port': server[1].split(':')[1].strip(),
                            'weight': server[2].strip()
                        })
                else:
                    server_matches = pattern_backend_servers_no_weight.findall(backend_servers_block)
                    for server in server_matches:
                        backend_servers.append({
                            'name': server[0].strip(),
                            'ip': server[1].split(':')[0].strip(),
                            'port': server[1].split(':')[1].strip()
                        })

                data.append({
                    'backend_name': current_backend_name,
                    'lb_method': lb_method,
                    'count_server': len(backend_servers),
                    'backend_servers': list(zip(backend_servers, range(1, len(backend_servers) + 1)))
                })
        
        # Hubungkan data frontend dengan backend
        for match in frontend_matches:
            frontend_name, port, protocol, use_backend_block = match
            frontend_block = content.split(f"frontend {frontend_name}")[1].split('frontend')[0]
            # print("frontend_block : ", frontend_block)
            
            # Dictionary untuk menyimpan mapping backend ke domain
            backend_to_domain = {}
            
            # Cari pasangan ACL dan use_backend dalam frontend_block
            acl_matches = re.finditer(r'acl\s+(\S+)\s+hdr\(host\)\s+-i\s+(\S+).*?\n.*?use_backend\s+(\S+)\s+if\s+\1', frontend_block, re.MULTILINE)
            
            # Cari domain yang terkait dalam frontend_block
            domain_names = set()
            for acl_match in acl_matches:
                acl_name, domain, backend = acl_match.groups()
                backend_to_domain[backend] = domain.strip()
                if backend == backend_name:
                    domain_names.add(domain.strip())

            # Ambil semua nilai use_backend di blok frontend
            use_backend_list = set()
            if use_backend_block:
                use_backend_matches = re.findall(r'use_backend\s+(\S+)', frontend_block)
                for backend in use_backend_matches:
                    if backend == backend_name:
                        use_backend_list.add(backend)

            # Tentukan domain HTTP atau TCP berdasarkan protokol
            domain_name_http = ", ".join(domain_names) if protocol == 'http' else set()
            domain_name_tcp = ", ".join(domain_names) if protocol == 'tcp' else set()

            # Tampilkan informasi frontend sesuai permintaan
            # if protocol == 'http':
            #     print("frontend", [frontend_name, port, protocol, domain_name_http, use_backend_list or set()])
            # elif protocol == 'tcp':
            #     print("frontend", [frontend_name, port, protocol, domain_name_tcp, use_backend_list or set()])

            # Temukan entry backend terkait dalam data untuk menambahkan detail
            for entry in data:
                if entry['backend_name'] == backend_name and backend_name in use_backend_list:
                    entry['frontend_name'] = frontend_name
                    entry['protocol'] = protocol
                    entry['port'] = port
                    entry['domain_name_http'] = domain_name_http if protocol == 'http' else set()
                    entry['domain_name_tcp'] = domain_name_tcp if protocol == 'tcp' else set()
                    entry['use_backend'] = use_backend_list

    return data


first_http_entry = True
def save_to_file(data):
    is_haproxy_name = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
    global first_http_entry
    haproxy_name = is_haproxy_name
    port = data.get('port')
    protocol = data.get('protocol')
    lb_method = data.get('lb_method')
    use_ssl_http = data.get('use_ssl_http', False)
    use_ssl_tcp = data.get('use_ssl_tcp', False)
    ssl_cert_path_http = data.get('ssl_cert_path_http', '')
    ssl_cert_path_tcp = data.get('ssl_cert_path_tcp', '')
    backend_servers = data.get('backend_servers', [])
    domain_name_http = data.get('domain_name_http', '')
    domain_name_tcp = data.get('domain_name_tcp', '')

    # Jika protokol adalah http, kita tetap menggunakan http_name dan membedakan port 80 atau 443
    if protocol == 'http':
        port = 443 if ssl_cert_path_http else 80

    elif protocol == 'tcp':
        port = port

    with open(CONFIG_FILE_PATH, 'r') as haproxy_cfg:
        existing_config = haproxy_cfg.readlines()
    
    # Check if `acl is_default_acl hdr(host) -m reg -i` exists
    default_acl_present = any("acl is_default_acl hdr(host) -m reg -i" in line for line in existing_config)
    if protocol == 'http' and port == 80:
        if default_acl_present and not domain_name_http:
            return False, "Domain Name is required for existing HTTP configuration on port 80"
        elif not default_acl_present:
            first_http_entry = True
    
    # Buat ssl file jika tersedia
    if use_ssl_http and ssl_cert_path_http:
        cert_file_name = f"{haproxy_name}.pem"
        certificate(cert_file_name, ssl_cert_path_http)
    
    if use_ssl_tcp and ssl_cert_path_tcp:
        cert_file_name = f"{haproxy_name}.pem"
        certificate(cert_file_name, ssl_cert_path_tcp)
    
    # Cek jika "listen stats" sudah ada di file konfigurasi
    if 'listen stats' not in ''.join(existing_config):
        with open(CONFIG_FILE_PATH, 'a') as haproxy_cfg:
            haproxy_cfg.write(f"\nlisten stats\n")
            haproxy_cfg.write(f"        bind :9999\n")
            haproxy_cfg.write(f"        mode http\n")
            haproxy_cfg.write(f"        stats enable\n")
            haproxy_cfg.write(f"        stats hide-version\n")
            haproxy_cfg.write(f"        stats uri /stats\n")
            haproxy_cfg.write(f"        stats realm Haproxy\\ Statistics\n")

    # Flag pengecekan frontend dan domain
    frontend_found_http = False
    frontend_index_http = -1
    frontend_found_https = False
    frontend_index_https = -1
    domain_found_in_https = False
    domain_found_in_http = False
    domain_found_in_tcp = False
    frontend_found_tcp = False

    # Pengecekan HTTP dan HTTPS
    if protocol == 'http':
        for idx, line in enumerate(existing_config):
            if f"frontend" in line and "bind *:80" in existing_config[idx + 1]:
                frontend_found_http = True
                frontend_index_http = idx  # Simpan index posisi frontend 80
                if domain_found_in_http and f"hdr(host) -i {domain_found_in_http}" in existing_config[idx + 3]:
                    domain_found_in_http = True
                if "acl is_default_acl hdr(host) -m reg -i" in existing_config[idx + 3]:
                    first_http_entry = False
            elif f"frontend" in line and "bind *:443" in existing_config[idx + 1]:
                frontend_found_https = True
                frontend_index_https = idx  # Simpan index posisi frontend 443
                if domain_found_in_http and f"hdr(host) -i {domain_found_in_http}" in existing_config[idx + 3]:
                    domain_found_in_https = True
            if frontend_found_http and frontend_found_https:
                break

    # Pengecekan TCP untuk domain yang sama
    if protocol == 'tcp':
        for line in existing_config:
            if domain_name_tcp and f"hdr(host) -i {domain_name_tcp}" in line:
                domain_found_in_tcp = True
            if f"bind *:{port}" in line:
                frontend_found_tcp = True
                break

    # Cek apakah domain sudah digunakan
    if domain_name_http and (domain_found_in_http or domain_found_in_https or domain_found_in_tcp):
        return False, f"Domain {domain_name_http} is already in use."
    if domain_name_tcp and (domain_found_in_http or domain_found_in_https or domain_found_in_tcp):
        return False, f"Domain {domain_name_tcp} is already in use."
    if frontend_found_tcp:
        return False, f"Port {port} is already used in TCP protocol."
    
    # Handling HTTP (port 80) ACLs and frontend
    if frontend_found_http and port == 80 and not domain_found_in_http:
        if not domain_name_http and not first_http_entry:
            return False, "Domain Name is required for existing HTTP configuration on port 80"
        with open(CONFIG_FILE_PATH, 'w') as haproxy_cfg:
            for idx, line in enumerate(existing_config):
                haproxy_cfg.write(line)
                if idx == frontend_index_http + 3:
                    if not domain_name_http and first_http_entry:  # Only use default ACL if no domain and it's first entry
                        haproxy_cfg.write(f"        acl is_default_acl hdr(host) -m reg -i ^[^\\.]+\\.lawakobadu.my.id\\.id$\n")
                        haproxy_cfg.write(f"        use_backend {haproxy_name} if is_default_acl\n")
                        first_http_entry = False
                    else:
                        haproxy_cfg.write(f"        acl is_{haproxy_name}_acl hdr(host) -i {domain_name_http}\n")
                        haproxy_cfg.write(f"        use_backend {haproxy_name} if is_{haproxy_name}_acl\n")

    # Handling HTTP (port 443) ACLs and frontend
    elif frontend_found_https and port == 443 and not domain_found_in_https:
        if not domain_name_http:
            return False, "SSL Certificate path is required when SSL is enabled"
        with open(CONFIG_FILE_PATH, 'w') as haproxy_cfg:
            for idx, line in enumerate(existing_config):
                haproxy_cfg.write(line)
                if idx == frontend_index_https + 4:
                    haproxy_cfg.write(f"        acl is_{haproxy_name}_acl hdr(host) -i {domain_name_http}\n")
                    haproxy_cfg.write(f"        use_backend {haproxy_name} if is_{haproxy_name}_acl\n")

    elif not frontend_found_http or not frontend_found_https:
        with open(CONFIG_FILE_PATH, 'a') as haproxy_cfg:
            if protocol == 'http' and ssl_cert_path_http == "":
                haproxy_cfg.write(f"\nfrontend http-default\n")
                haproxy_cfg.write(f"        bind *:80\n")
                haproxy_cfg.write(f"        mode http\n")
                haproxy_cfg.write(f"        default_backend {haproxy_name}\n")
                if domain_name_http:
                    haproxy_cfg.write(f"        acl is_{haproxy_name}_acl hdr(host) -i {domain_name_http}\n")
                    haproxy_cfg.write(f"        use_backend {haproxy_name} if is_{haproxy_name}_acl\n")
            elif protocol == 'http' and ssl_cert_path_http != "":
                haproxy_cfg.write(f"\nfrontend https-default\n")
                haproxy_cfg.write(f"        bind *:443 ssl crt /etc/haproxy-dashboard/ssl/\n")
                haproxy_cfg.write(f"        redirect scheme https code 301 if !{{ ssl_fc }}\n")
                haproxy_cfg.write(f"        mode http\n")
                haproxy_cfg.write(f"        default_backend {haproxy_name}\n")
                if domain_name_http:
                    haproxy_cfg.write(f"        acl is_{haproxy_name}_acl hdr(host) -i {domain_name_http}\n")
                    haproxy_cfg.write(f"        use_backend {haproxy_name} if is_{haproxy_name}_acl\n")
            elif protocol == 'tcp' and ssl_cert_path_tcp == "":
                haproxy_cfg.write(f"\nfrontend {haproxy_name}\n")
                haproxy_cfg.write(f"        bind *:{port}\n")
                haproxy_cfg.write(f"        mode tcp\n")
                haproxy_cfg.write(f"        default_backend {haproxy_name}\n")
                haproxy_cfg.write(f"        acl is_default_acl hdr(host) -m reg -i ^[^\\.]+\\.lawakobadu.my.id\\.id$\n")
                haproxy_cfg.write(f"        use_backend {haproxy_name} if is_default_acl\n")
            elif protocol == 'tcp' and ssl_cert_path_tcp != "":
                haproxy_cfg.write(f"\nfrontend {haproxy_name}\n")
                haproxy_cfg.write(f"        bind *:{port} ssl crt /etc/haproxy-dashboard/ssl/{haproxy_name}.pem\n")
                haproxy_cfg.write(f"        redirect scheme https code 301 if !{{ ssl_fc }}\n")
                haproxy_cfg.write(f"        mode tcp\n")
                haproxy_cfg.write(f"        default_backend {haproxy_name}\n")
                haproxy_cfg.write(f"        acl is_{haproxy_name}_acl hdr(host) -i {domain_name_tcp}\n")
                haproxy_cfg.write(f"        use_backend {haproxy_name} if is_{haproxy_name}_acl\n")

    # Adding backend servers
    with open(CONFIG_FILE_PATH, 'a') as haproxy_cfg:
        if lb_method == 'roundrobin':
            haproxy_cfg.write(f"\nbackend {haproxy_name}\n")
            haproxy_cfg.write(f"        balance {lb_method}\n")
            for backend_server_info in backend_servers:
                backend_server_name, backend_server_ip, backend_server_port, backend_server_weight = backend_server_info
                if backend_server_name and backend_server_ip and backend_server_port and backend_server_weight:
                    haproxy_cfg.write(f"        server {backend_server_name} {backend_server_ip}:{backend_server_port} weight {backend_server_weight} check\n")
        else:
            haproxy_cfg.write(f"\nbackend {haproxy_name}\n")
            haproxy_cfg.write(f"        balance {lb_method}\n")
            for backend_server_info in backend_servers:
                backend_server_name, backend_server_ip, backend_server_port = backend_server_info
                if backend_server_name and backend_server_ip and backend_server_port:
                    haproxy_cfg.write(f"        server {backend_server_name} {backend_server_ip}:{backend_server_port} check\n")

    # return flash("Frontend and Backend added successfully.", "success")
    return {'success': True, 'message': "Frontend and Backend added successfully."}


def delete_conf(backend_name):
    with open(CONFIG_FILE_PATH, 'r') as file:
        lines = file.readlines()

    new_lines = []
    skip = False
    remove_tcp_section = False
    default_acl_related_backend = None  # Store backend related to is_default_acl
    
    # Patterns to match specific lines for deletion
    acl_pattern = re.compile(rf'^\s*acl\s+is_{backend_name}_acl\b')
    acl_default_pattern = re.compile(r'^\s*acl\s+is_default_acl\s+\b')
    use_backend_pattern = re.compile(rf'^\s*use_backend\s+{backend_name}\b')
    backend_pattern = re.compile(rf'^\s*backend\s+{backend_name}\b')
    frontend_pattern = re.compile(r'^\s*frontend\s+(\w+)\b')
    use_backend_default_acl_pattern = re.compile(r'^\s*use_backend\s+(\w+)\s+if\s+is_default_acl\b')

    # First pass: find backend associated with default ACL
    for line in lines:
        default_acl_backend_match = use_backend_default_acl_pattern.match(line)
        if default_acl_backend_match:
            default_acl_related_backend = default_acl_backend_match.group(1)
            break

    # Second pass: process and filter lines
    for i, line in enumerate(lines):
        # Detect if this frontend is associated with the backend being removed in TCP mode
        frontend_match = frontend_pattern.match(line)
        if frontend_match:
            current_frontend_name = frontend_match.group(1)

            # Check if this frontend is in TCP mode
            if any("mode tcp" in lines[j] for j in range(i + 1, min(i + 6, len(lines)))):
                if current_frontend_name == backend_name:
                    remove_tcp_section = True
                else:
                    remove_tcp_section = False

        # Skip the default ACL line if it is related to the backend being deleted
        if acl_default_pattern.match(line) and default_acl_related_backend == backend_name:
            continue

        # Skip lines associated with the backend being deleted
        if backend_pattern.match(line) or (remove_tcp_section and frontend_match) or (default_acl_related_backend == backend_name and line.startswith(f"backend {default_acl_related_backend}")):
            skip = True
        elif skip and re.match(r'^\s*(frontend|backend)\b', line):
            skip = False

        # Skip ACL and use_backend lines only if they match the specific backend being deleted
        if acl_pattern.match(line) or use_backend_pattern.match(line):
            continue

        # Add only lines that aren't skipped
        if not skip:
            new_lines.append(line)

    # Overwrite the configuration file with the new content
    with open(CONFIG_FILE_PATH, 'w') as file:
        file.writelines(new_lines)

    return new_lines


def haproxy_info():
    backend_info = []
    current_frontend = None
    protocol = None
    port = None
    lb_method = ''
    acl_rules = {}
    backend_name = ''
    ssl_status = 'none'  # Default SSL status

    with open(CONFIG_FILE_PATH, 'r') as haproxy_cfg:
        lines = haproxy_cfg.readlines()

    for line in lines:
        line = line.strip()

        # Detect frontend section and reset protocol, port, and SSL status
        if line.startswith('frontend'):
            current_frontend = line.split()[1]
            protocol = 'http'
            port = None
            ssl_status = 'none'

        # Detect mode directive to set protocol to tcp if applicable
        if line.startswith('mode') and current_frontend:
            protocol = line.split()[1]

        # Detect bind directive in frontend section
        if line.startswith('bind') and current_frontend:
            port = line.split(':')[1].split()[0]
            ssl_status = 'manual' if 'ssl crt' in line else 'none'
            domain_or_ip = f"https://{request.host.split(':')[0]}" if ssl_status == "manual" else f"http://{request.host.split(':')[0]}"

        # Capture ACL rules with domain names
        if line.startswith('acl is_') and 'hdr(host) -i' in line:
            acl_name = line.split()[1]
            domain = line.split()[-1]
            acl_rules[acl_name] = domain

        # Detect use_backend and associate with ACL
        if line.startswith('use_backend'):
            backend_name = line.split()[1]
            acl_name = line.split()[-1]
            domain_or_ip = acl_rules.get(acl_name, request.host.split(':')[0])
            if protocol == 'tcp' and port:
                domain_or_ip = f"{domain_or_ip}:{port}"
            domain_or_ip = f"https://{domain_or_ip}" if ssl_status == "manual" else f"http://{domain_or_ip}"

            if backend_name not in ['http-default', 'https-default']:
                backend_info.append({
                    'backend_name': backend_name,
                    'protocol': protocol,
                    'port': port,
                    'domain': domain_or_ip,
                    'ssl': ssl_status,
                    'lb_method': '',
                    'backend_servers': []  # Add backend_servers list
                })

        # Detect backend section without corresponding ACL and assign default IP
        if line.startswith('backend'):
            backend_name = line.split()[1]
            lb_method = ''
            if not any(backend['backend_name'] == backend_name for backend in backend_info) and backend_name not in ['http-default', 'https-default']:
                domain_or_ip = f"{request.host.split(':')[0]}:{port}" if protocol == 'tcp' and port else request.host.split(':')[0]
                domain_or_ip = f"https://{domain_or_ip}" if ssl_status == "manual" else f"http://{domain_or_ip}"
                backend_info.append({
                    'backend_name': backend_name,
                    'protocol': protocol,
                    'port': port,
                    'domain': domain_or_ip,
                    'ssl': ssl_status,
                    'lb_method': '',
                    'backend_servers': []  # Add backend_servers list
                })

        # Detect balance directive in backend section to set lb_method
        if line.startswith('balance') and backend_name:
            lb_method = line.split()[1]
            for backend in backend_info:
                if backend['backend_name'] == backend_name:
                    backend['lb_method'] = lb_method

        # Detect server entries in the backend section
        if line.startswith('server') and backend_name:
            server_info = line.split()
            server_name = server_info[1]
            server_ip = server_info[2].split(':')[0]
            server_port = server_info[2].split(':')[1] if ':' in server_info[2] else None

            # Append server information to the correct backend entry
            for backend in backend_info:
                if backend['backend_name'] == backend_name:
                    backend['backend_servers'].append({
                        'name': server_name,
                        'ip': server_ip,
                        'port': server_port
                    })

    return backend_info


@app.route("/", methods=["GET", "POST"])
def index():
    if session.get('logged_in'):
        return '<script>alert("Forbidden access"); window.location.href = "/home";</script>'

    is_user = is_user_exist()

    if request.method == "POST":
        data = request.get_json()

        if not data or 'username' not in data or 'password' not in data:
            return make_response('Missing credentials', 400)

        username = data['username']
        password = data['password']

        # if username in is_user and is_user[username]['password'] == password:
        if username in is_user and check_password_hash(is_user[username]['password'], password):
            # session.permanent = True
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


def haproxy_stats():
    # Mengambil data CSV dari URL
    csv_url = f"http://{request.host.split(':')[0]}:9999/stats;csv"
    
    try:
        response = requests.get(csv_url)
        response.raise_for_status()  # Untuk menangani HTTP error yang lain
        decoded_content = response.content.decode('utf-8')

        # Mem-parsing CSV
        csv_reader = csv.reader(decoded_content.splitlines(), delimiter=',')
        data = list(csv_reader)

        # Memproses data CSV untuk frontend dan backend
        processed_data = []
        backend_names = set()  # Set untuk menyimpan nama backend yang unik

        for index, row in enumerate(data):
            # Memastikan row tidak kosong dan memiliki kolom yang cukup
            if len(row) > 50:
                # Memastikan ini bukan baris header
                if index == 0:  # Jika ini adalah baris pertama (header), lewati
                    continue
                if row[0] == 'stats' and row[1] in ['FRONTEND', 'BACKEND']:
                    continue

                # Menangkap baris FRONTEND
                if row[1] == 'FRONTEND':
                    processed_data.append({
                        'pxname': row[0],
                        'svname': row[1],
                        'status': row[17],
                    })
                # Menangkap baris BACKEND dan nama backend lainnya
                elif row[1] == 'BACKEND' or row[1] not in ['FRONTEND']:
                    processed_data.append({
                        'pxname': row[0],
                        'svname': row[1],
                        'status': row[17],
                    })
                    backend_names.add(row[0])  # Menyimpan nama backend unik

        return processed_data, backend_names

    except ConnectionError:
        # Jika terjadi error koneksi, kembalikan data kosong dan backend_names kosong
        return [], set()


@app.route("/home", methods=['GET', 'POST'])
def home():
    if not session.get('logged_in'):
        return '<script>alert("You must login or session time has been expired"); window.location.href = "/";</script>'

    file_name = request.args.get('file_name')

    haproxy_data = haproxy_info()
    haproxy_exists = is_haproxy_exist()
    haproxy_stats_data, backend_names = haproxy_stats()

    # Baca konfigurasi HAProxy dari file
    with open(CONFIG_FILE_PATH, 'r') as f:
        content = f.read().strip()

        # Gabungan regex untuk frontend dan backend
        pattern = re.compile(
            r'frontend\s+(\S+)\s+.*?bind\s+(\S+):(\d+).*?\n\s+mode\s+(\S+)'
            r'backend\s+(\S+)\s+balance\s+(\S+)(.*?)\s*(?=frontend|\Z)', 
            re.DOTALL
        )
        
        matches = pattern.findall(content)

        # Menyimpan data haproxy
        for match in matches:
            frontend_name = match[0].strip()
            port = match[2].strip()
            domain_name = match[3].strip() if match[3] else None
            protocol = match[4].strip()
            backend_name = match[5].strip()
            lb_method = match[6].strip()
            backend_servers_block = match[7].strip()

            # Pola regex untuk server backend
            pattern_backend_servers = re.compile(
                r'server\s+(\w+)\s+([\d.:]+)(?:\s+weight\s+(\d+))?\s+check'
            )
            
            backend_servers = []
            server_matches = pattern_backend_servers.findall(backend_servers_block)
            
            for server in server_matches:
                backend_servers.append({
                    'name': server[0].strip(),
                    'ip': server[1].split(':')[0].strip(),
                    'port': server[1].split(':')[1].strip() if ':' in server[1] else None,
                    'weight': server[2].strip() if len(server) > 2 else None
                })

            # Tambahkan backend servers ke data haproxy
            for haproxy in haproxy_data:
                if haproxy['backend_name'] == backend_name:
                    haproxy['backend_servers'] = backend_servers

    # Proses status backend untuk tiap haproxy
    for haproxy in haproxy_data:
        haproxy['backends'] = []  # List untuk menyimpan status tiap backend

        # Cek status tiap backend
        for stat in haproxy_stats_data:
            if stat['pxname'] == haproxy['backend_name'] and stat['svname'] != 'FRONTEND':
                if stat['svname'] != 'BACKEND':
                    backend_status = {
                        'name': stat['svname'],
                        'status': 'Active' if stat['status'] in ['UP', 'OPEN'] else 'Error',
                        'ip': None  # Placeholder untuk IP
                    }
                    # Temukan IP dari backend servers
                    for server in haproxy.get('backend_servers', []):
                        if backend_status['name'] == server['name']:
                            backend_status['ip'] = server['ip']  # Assign IP yang benar
                    haproxy['backends'].append(backend_status)

    return render_template(
        'home.html',
        haproxy_data=haproxy_data,
        haproxy_exists=haproxy_exists,
        file_name=file_name,
        haproxy_stats=haproxy_stats_data
    )


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route("/add", methods=['GET', 'POST'])
def add():
    if not session.get('logged_in'):
        return '<script>alert("You must login or session time has been expired"); window.location.href = "/";</script>'
    
    global first_http_entry

    with open(CONFIG_FILE_PATH, 'r') as haproxy_cfg_read:
        existing_config = haproxy_cfg_read.read()
    
    if request.method == 'POST':
        # Get data from the form
        backend_server_names = request.form.getlist('backend_server_names')
        backend_server_ips = request.form.getlist('backend_server_ips')
        backend_server_ports = request.form.getlist('backend_server_ports')

        if not backend_server_names or any(name == '' for name in backend_server_names):
            flash("All backend server names are required", "danger")
            return render_template('HAProxy/add.html')

        # Validate alphanumeric input
        alphanumeric_pattern = re.compile(r'^[A-Za-z0-9]+$')
        for name in backend_server_names:
            if not alphanumeric_pattern.match(name):
                flash(f"Backend server name '{name}' is invalid. Only letters and numbers are allowed. No spaces.", "danger")
                return render_template('HAProxy/add.html')

        if not backend_server_ips or any(ip == '' for ip in backend_server_ips):
            flash("All backend server IPs are required", "danger")
            return render_template('HAProxy/add.html')

        if not backend_server_ports or any(port == '' for port in backend_server_ports):
            flash("All backend server ports are required", "danger")
            return render_template('HAProxy/add.html')

        # Get the selected protocol
        protocol = request.form.get('protocol', '')

        # Check if SSL is enabled for HTTP
        use_ssl_http = 'use_ssl_http' in request.form and request.form['use_ssl_http'] == 'on'
        ssl_cert_path_http = ''
        domain_name_http = ''

        # Handle HTTP domain name logic
        if protocol == 'http':
            http_port_80_exists = "bind *:80" in existing_config and "mode http" in existing_config and "acl is_default_acl hdr(host) -m reg -i" in existing_config

            if http_port_80_exists:
                domain_name_http = request.form.get('domain_name_http', '')
                if not domain_name_http:
                    flash("Domain Name is required for existing HTTP configuration on port 80", "danger")
                    return render_template('HAProxy/add.html')
                elif not http_port_80_exists:
                    first_http_entry = True
            else:
                domain_name_http = request.form.get('domain_name_http', '')

            if use_ssl_http:
                ssl_cert_path_http = request.form.get('ssl_cert_path_http', '')
                domain_name_http = request.form.get('domain_name_http', '')

                if not ssl_cert_path_http:
                    flash("SSL Certificate path is required when SSL is enabled", "danger")
                    return render_template('HAProxy/add.html')

                # Bind to port 443 if SSL cert path is provided
                if not domain_name_http:
                    flash("Domain Name is required when SSL is enabled", "danger")
                    return render_template('HAProxy/add.html')

        # Check if SSL is enabled for TCP
        use_ssl_tcp = 'use_ssl_tcp' in request.form and request.form['use_ssl_tcp'] == 'on'
        ssl_cert_path_tcp = ''
        domain_name_tcp = ''

        if protocol == 'tcp':
            if use_ssl_tcp:
                ssl_cert_path_tcp = request.form.get('ssl_cert_path_tcp', '')
                domain_name_tcp = request.form.get('domain_name_tcp', '')

                if not ssl_cert_path_tcp:
                    flash("SSL Certificate path is required when SSL is enabled", "danger")
                    return render_template('HAProxy/add.html')

                if not domain_name_tcp:
                    flash("Domain Name is required when SSL is enabled", "danger")
                    return render_template('HAProxy/add.html')

        # Prepare data after validation
        lb_method = request.form['lb_method']
        port = request.form['port']

        data = {
            'port': port,
            'lb_method': lb_method,
            'protocol': protocol,
            'use_ssl_http': use_ssl_http,
            'use_ssl_tcp': use_ssl_tcp,
            'ssl_cert_path_http': ssl_cert_path_http,
            'ssl_cert_path_tcp': ssl_cert_path_tcp,
            'domain_name_http': domain_name_http,
            'domain_name_tcp': domain_name_tcp
        }

        if lb_method == 'roundrobin':
            # Include weights for roundrobin
            data['backend_servers'] = list(zip(
                backend_server_names,
                backend_server_ips,
                backend_server_ports,
                request.form.getlist('backend_server_weights')
            ))
        else:
            # For other methods, omit weights
            data['backend_servers'] = list(zip(
                backend_server_names,
                backend_server_ips,
                backend_server_ports
            ))

        # ** Tambahan Logika Pengecekan Domain dan Port **
        domain_found_in_http = domain_name_http and re.search(rf"hdr\(host\) -i {re.escape(domain_name_http)}", existing_config)
        domain_found_in_https = domain_name_http and re.search(rf"hdr\(host\) -i {re.escape(domain_name_http)}", existing_config)
        domain_found_in_tcp = domain_name_tcp and re.search(rf"hdr\(host\) -i {re.escape(domain_name_tcp)}", existing_config)

        # Check if domain name is already in use
        if domain_name_http and (domain_found_in_http or domain_found_in_https or domain_found_in_tcp):
            flash(f"Domain {domain_name_http} is already in use.", "danger")
            return render_template('HAProxy/add.html')
        if domain_name_tcp and (domain_found_in_http or domain_found_in_https or domain_found_in_tcp):
            flash(f"Domain {domain_name_tcp} is already in use.", "danger")
            return render_template('HAProxy/add.html')
        
        # Check if TCP port is already in use
        if protocol == "tcp" and f"bind *:{port}" in existing_config:
            flash(f"Port {port} is already use in TCP protocol", "danger")
            return render_template('HAProxy/add.html', **data)
        
        # Save the configuration
        save_to_file(data)

        if 'save_reload_create' in request.form:
            # Run haproxy -c -V -f to check configuration
            check_result = subprocess.run(['haproxy', '-c', '-V', '-f', CONFIG_FILE_PATH], capture_output=True, text=True)
            check_output = check_result.stdout

            # If an error occurs, add it to the output
            if check_result.returncode != 0:
                error_message = check_result.stderr
                check_output += f"\n\nError occurred:\n{error_message}"
            else:
                # If no errors, reload HAProxy
                reload_result = subprocess.run(['systemctl', 'reload', 'haproxy', CONFIG_FILE_PATH], capture_output=True, text=True)
                check_output += f"\n\nHAProxy Restart Output:\n{reload_result.stdout}"

        return redirect(url_for('home'))

    return render_template('HAProxy/add.html')


@app.route("/edit/<backend_name>", methods=['GET', 'POST'])
def edit(backend_name):
    if not session.get('logged_in'):
        return '<script>alert("You must login or session time has been expired"); window.location.href = "/";</script>'
    
    ssl_cert_content_http = ''
    ssl_cert_content_tcp = ''
    domain_name_http = ''
    domain_name_tcp = ''
    global first_http_entry

    # Get the current configuration for the backend
    data = read_from_file(backend_name)
    item = next((d for d in data if d['backend_name'] == backend_name), None)

    if request.method == 'POST':
        if item:
            # Get data from the form
            backend_server_names = request.form.getlist('backend_server_names')
            backend_server_ips = request.form.getlist('backend_server_ips')
            backend_server_ports = request.form.getlist('backend_server_ports')

            # Validate backend server names
            if not backend_server_names or any(name == '' for name in backend_server_names):
                flash("All backend server names are required", "danger")
                return render_template('HAProxy/edit.html', **item, ssl_cert_path_http=ssl_cert_content_http, ssl_cert_path_tcp=ssl_cert_content_tcp)

            # Validate alphanumeric input
            alphanumeric_pattern = re.compile(r'^[A-Za-z0-9]+$')
            for name in backend_server_names:
                if not alphanumeric_pattern.match(name):
                    flash(f"Backend server name '{name}' is invalid. Only letters and numbers are allowed. No spaces.", "danger")
                    return render_template('HAProxy/edit.html', **item, ssl_cert_path_http=ssl_cert_content_http, ssl_cert_path_tcp=ssl_cert_content_tcp)

            # Validate IPs and ports
            if not backend_server_ips or any(ip == '' for ip in backend_server_ips):
                flash("All backend server IPs are required", "danger")
                return render_template('HAProxy/edit.html', **item, ssl_cert_path_http=ssl_cert_content_http, ssl_cert_path_tcp=ssl_cert_content_tcp)

            if not backend_server_ports or any(port == '' for port in backend_server_ports):
                flash("All backend server ports are required", "danger")
                return render_template('HAProxy/edit.html', **item, ssl_cert_path_http=ssl_cert_content_http, ssl_cert_path_tcp=ssl_cert_content_tcp)

            # Get the protocol and other form data
            protocol = request.form.get('protocol', '')
            port = request.form['port']
            lb_method = request.form['lb_method']

            # Handle HTTP protocol specific validation
            if protocol == 'http':
                # Delete old configuration and SSL certificates
                delete_conf(backend_name)
                
                ssl_cert_file_http = os.path.join(SSL_FILE_PATH, f"{backend_name}.pem")

                if os.path.exists(ssl_cert_file_http):
                    os.remove(ssl_cert_file_http)
                
                # Read the existing HAProxy configuration
                with open(CONFIG_FILE_PATH, 'r') as haproxy_cfg_read:
                    existing_config = haproxy_cfg_read.read()

                    use_ssl_http = 'use_ssl_http' in request.form and request.form['use_ssl_http'] == 'on'
                    ssl_cert_path_http = ''
                    
                    # Check for existing HTTP configuration on port 80
                    http_port_80_exists = "bind *:80" in existing_config and "mode http" in existing_config and "acl is_default_acl hdr(host) -m reg -i" in existing_config

                    if http_port_80_exists:
                        domain_name_http = request.form.get('domain_name_http', '')
                        if not domain_name_http:
                            flash("Domain Name is required for existing HTTP configuration on port 80", "danger")
                            return render_template('HAProxy/edit.html', **item, ssl_cert_path_http=ssl_cert_content_http, ssl_cert_path_tcp=ssl_cert_content_tcp)
                        elif not http_port_80_exists:
                            first_http_entry = True
                    else:
                        domain_name_http = request.form.get('domain_name_http', '')

                    # Handle SSL for HTTP
                    if use_ssl_http:
                        ssl_cert_path_http = request.form.get('ssl_cert_path_http', '')
                        if not ssl_cert_path_http:
                            flash("SSL Certificate path is required when SSL is enabled", "danger")
                            return render_template('HAProxy/edit.html', **item, ssl_cert_path_http=ssl_cert_content_http, ssl_cert_path_tcp=ssl_cert_content_tcp)
                        if not domain_name_http:
                            flash("Domain Name is required when SSL is enabled", "danger")
                            return render_template('HAProxy/edit.html', **item, ssl_cert_path_http=ssl_cert_content_http, ssl_cert_path_tcp=ssl_cert_content_tcp)
                    
                    # Check if domain is already in use (excluding current backend)
                    domain_found_in_http = domain_name_http and re.search(rf"hdr\(host\) -i {re.escape(domain_name_http)}", existing_config)
                    domain_found_in_https = domain_name_http and re.search(rf"hdr\(host\) -i {re.escape(domain_name_http)}", existing_config)
                    
                    if domain_name_http and (domain_found_in_http or domain_found_in_https):
                        # Check if the domain is used by a different backend
                        current_backend_pattern = rf"backend\s+{re.escape(backend_name)}.*?(?=backend|\Z)"
                        current_backend_config = re.search(current_backend_pattern, existing_config, re.DOTALL)
                        if current_backend_config and domain_name_http not in current_backend_config.group():
                            flash(f"Domain {domain_name_http} is already in use.", "danger")
                            return render_template('HAProxy/edit.html', **item, ssl_cert_path_http=ssl_cert_content_http, ssl_cert_path_tcp=ssl_cert_content_tcp)

                item.update({
                    'port': port,
                    'protocol': protocol,
                    'use_ssl_http': use_ssl_http,
                    'ssl_cert_path_http': ssl_cert_path_http,
                    'domain_name_http': domain_name_http,
                    'lb_method': lb_method
                })

            # Handle TCP protocol specific validation
            elif protocol == 'tcp':
                # Delete old configuration and SSL certificates
                delete_conf(backend_name)
                
                ssl_cert_file_tcp = os.path.join(SSL_FILE_PATH, f"{backend_name}.pem")

                if os.path.exists(ssl_cert_file_tcp):
                    os.remove(ssl_cert_file_tcp)

                # Check port if already used
                with open(CONFIG_FILE_PATH, 'r') as haproxy_cfg_read:
                    existing_config = haproxy_cfg_read.read()
                
                    use_ssl_tcp = 'use_ssl_tcp' in request.form and request.form['use_ssl_tcp'] == 'on'
                    domain_name_tcp = request.form.get('domain_name_tcp', '')
                    ssl_cert_path_tcp = request.form.get('ssl_cert_path_tcp', '') if use_ssl_tcp else ''

                    # Validate SSL requirements for TCP
                    if use_ssl_tcp:
                        if not ssl_cert_path_tcp:
                            flash("SSL Certificate path is required when SSL is enabled", "danger")
                            return render_template('HAProxy/edit.html', **item, ssl_cert_path_http=ssl_cert_content_http, ssl_cert_path_tcp=ssl_cert_content_tcp)
                        if not domain_name_tcp:
                            flash("Domain Name is required when SSL is enabled", "danger")
                            return render_template('HAProxy/edit.html', **item, ssl_cert_path_http=ssl_cert_content_http, ssl_cert_path_tcp=ssl_cert_content_tcp)
                    
                    # Check if domain is already in use (excluding current backend)
                    domain_found_in_tcp = domain_name_tcp and re.search(rf"hdr\(host\) -i {re.escape(domain_name_tcp)}", existing_config)
                    if domain_found_in_tcp:
                        current_backend_pattern = rf"backend\s+{re.escape(backend_name)}.*?(?=backend|\Z)"
                        current_backend_config = re.search(current_backend_pattern, existing_config, re.DOTALL)
                        if current_backend_config and domain_name_tcp not in current_backend_config.group():
                            flash(f"Domain {domain_name_tcp} is already in use.", "danger")
                            return render_template('HAProxy/edit.html', **item, ssl_cert_path_http=ssl_cert_content_http, ssl_cert_path_tcp=ssl_cert_content_tcp)

                item.update({
                    'port': port,
                    'protocol': protocol,
                    'use_ssl_tcp': use_ssl_tcp,
                    'ssl_cert_path_tcp': ssl_cert_path_tcp,
                    'domain_name_tcp': domain_name_tcp,
                    'lb_method': lb_method
                })

            # Update backend servers based on load balancing method
            if lb_method == 'roundrobin':
                item['backend_servers'] = list(zip(
                    backend_server_names,
                    backend_server_ips,
                    backend_server_ports,
                    request.form.getlist('backend_server_weights')
                ))
            else:
                item['backend_servers'] = list(zip(
                    backend_server_names,
                    backend_server_ips,
                    backend_server_ports
                ))
            
            # Check port if already used
            with open(CONFIG_FILE_PATH, 'r') as haproxy_cfg_read:
                existing_config = haproxy_cfg_read.read()

            # Check if TCP port is already in use
                if item['protocol'] == 'tcp' and f"bind *:{item['port']}" in existing_config:
                    flash(f"Port {item['port']} is already used in TCP protocol", "danger")
                    return render_template('HAProxy/edit.html', **item, ssl_cert_path_http=ssl_cert_content_http, ssl_cert_path_tcp=ssl_cert_content_tcp)
            
            # Save the new configuration
            save_to_file(item)

            # Handle configuration validation and reload
            if 'save_reload_update' in request.form:
                check_result = subprocess.run(['haproxy', '-c', '-V', '-f', CONFIG_FILE_PATH], capture_output=True, text=True)
                check_output = check_result.stdout

                if check_result.returncode != 0:
                    error_message = check_result.stderr
                    check_output += f"\n\nError occurred:\n{error_message}"
                else:
                    reload_result = subprocess.run(['systemctl', 'reload', 'haproxy'], capture_output=True, text=True)
                    check_output += f"\n\nHAProxy Restart Output:\n{reload_result.stdout}"

            return redirect(url_for('home'))

    # Read SSL certificate content for template rendering
    ssl_cert_file_http = os.path.join(SSL_FILE_PATH, f"{backend_name}.pem")
    if os.path.isfile(ssl_cert_file_http):
        with open(ssl_cert_file_http, 'r') as file:
            ssl_cert_content_http = file.read()

    ssl_cert_file_tcp = os.path.join(SSL_FILE_PATH, f"{backend_name}.pem")
    if os.path.isfile(ssl_cert_file_tcp):
        with open(ssl_cert_file_tcp, 'r') as file:
            ssl_cert_content_tcp = file.read()

    return render_template('HAProxy/edit.html', **item, ssl_cert_path_http=ssl_cert_content_http, ssl_cert_path_tcp=ssl_cert_content_tcp)


@app.route("/delete/<backend_name>/<file_name>", methods=['POST'])
def delete(backend_name, file_name):
    # Hapus konfigurasi backend
    modified_lines = delete_conf(backend_name)

    # Tulis kembali perubahan ke file konfigurasi
    with open(CONFIG_FILE_PATH, 'w') as file:
        file.writelines(modified_lines)

    # Hapus file SSL terkait jika ada
    key_file = os.path.join(SSL_FILE_PATH, file_name + ".pem")
    if os.path.exists(key_file):
        os.remove(key_file)

    # Check if the save_reload_delete button was pressed
    if 'save_reload_delete' in request.form:
        # Validate HAProxy configuration
        check_result = subprocess.run(['haproxy', '-c', '-f', CONFIG_FILE_PATH], capture_output=True, text=True)
        check_output = check_result.stdout

        if check_result.returncode != 0:
            error_message = check_result.stderr
            check_output += f"\n\nError occurred:\n{error_message}"
            return redirect(url_for('home'))

        # Restart HAProxy if validation succeeds
        reload_result = subprocess.run(['systemctl', 'reload', 'haproxy'], capture_output=True, text=True)
        check_output += f"\n\nHAProxy Restart Output:\n{reload_result.stdout}"

        return redirect(url_for('home'))

    return render_template('home.html')


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_password():
    if not session.get('logged_in'):
        return '<script>alert("You must login or session time has been expired"); window.location.href = "/";</script>'
    
    is_user = is_user_exist()
    username = session.get('username')

    if username not in is_user:
        return '<script>alert("User not found"); window.location.href = "/";</script>'

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        password_confirmation = request.form.get('password_confirmation')

        if not new_password or not password_confirmation:
            return '<script>alert("Please fill your password"); window.location.href = "/reset_password";</script>'

        if new_password == password_confirmation:
            hashed_password = generate_password_hash(new_password)
            is_user[username]['password'] = hashed_password
            save_users(is_user)
            session.clear()
            return '<script>alert("The password has been reset"); window.location.href = "/";</script>'
        else:
            return '<script>alert("Password not matches"); window.location.href = "/reset_password";</script>'
    
    return render_template('reset_password.html')

@app.errorhandler(404)
def not_found_error(error):
    previous_page = request.referrer if request.referrer else url_for('home')
    return render_template('errors/404.html', previous_page=previous_page), 404

@app.errorhandler(500)
def internal_error(error):
    previous_page = request.referrer if request.referrer else url_for('home')
    return render_template('errors/500.html', previous_page=previous_page), 500

config2 = configparser.ConfigParser()
config2.read('/etc/haproxy-dashboard/ssl.ini')

certificate_path = config2.get('ssl', 'certificate_path')
private_key_path = config2.get('ssl', 'private_key_path')

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
ssl_context.load_cert_chain(certfile=certificate_path, keyfile=private_key_path)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, ssl_context=ssl_context)
