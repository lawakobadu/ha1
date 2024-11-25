from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.utils.haproxy_config import read_from_file, save_to_file, delete_conf, haproxy_info, first_http_entry
from app.utils.file_ops import haproxy_stats, is_haproxy_exist, CONFIG_FILE_PATH, SSL_FILE_PATH
import re, subprocess, os

haproxy_bp = Blueprint('haproxy', __name__)

@haproxy_bp.route("/home", methods=['GET', 'POST'])
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

@haproxy_bp.route("/add", methods=['GET', 'POST'])
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

        return redirect(url_for('haproxy.home'))

    return render_template('HAProxy/add.html')


@haproxy_bp.route("/edit/<backend_name>", methods=['GET', 'POST'])
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

            return redirect(url_for('haproxy.home'))

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


@haproxy_bp.route("/delete/<backend_name>/<file_name>", methods=['POST'])
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
            return redirect(url_for('haproxy.home'))

        # Restart HAProxy if validation succeeds
        reload_result = subprocess.run(['systemctl', 'reload', 'haproxy'], capture_output=True, text=True)
        check_output += f"\n\nHAProxy Restart Output:\n{reload_result.stdout}"

        return redirect(url_for('haproxy.home'))

    return render_template('home.html')