from app import create_app
from OpenSSL import SSL
import configparser
import ssl

app = create_app()

config2 = configparser.ConfigParser()
config2.read('/etc/haproxy-dashboard/ssl.ini')

certificate_path = config2.get('ssl', 'certificate_path')
private_key_path = config2.get('ssl', 'private_key_path')

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
ssl_context.load_cert_chain(certfile=certificate_path, keyfile=private_key_path)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, ssl_context=ssl_context)