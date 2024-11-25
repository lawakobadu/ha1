from flask import request
from app.utils.file_ops import CONFIG_FILE_PATH, certificate
import re, secrets, string

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