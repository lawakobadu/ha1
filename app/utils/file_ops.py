from flask import request
import os, json, csv, requests
from functools import wraps
from requests.exceptions import ConnectionError

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


def is_haproxy_exist():
    with open(CONFIG_FILE_PATH, 'r') as haproxy_cfg:
        content = haproxy_cfg.read()
        if "frontend " in content or "backend " in content:
            return True
    return False


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