import os
from flask import Flask, render_template, request, jsonify
import socket
import requests
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

def deep_crawl(url, max_depth=3):
    visited = set()
    hosts = set()

    def crawl(current_url, depth):
        if depth > max_depth or current_url in visited:
            return
        visited.add(current_url)
        try:
            resp = requests.get(current_url, timeout=5, verify=False)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, 'html.parser')
            parsed_base = urlparse(current_url)
            base_domain = parsed_base.netloc

            for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe']):
                for attr in ['href', 'src']:
                    link = tag.get(attr)
                    if link:
                        full_url = urljoin(current_url, link)
                        parsed = urlparse(full_url)
                        if parsed.hostname:
                            hosts.add(parsed.hostname)
                        if parsed.netloc == base_domain and full_url not in visited:
                            crawl(full_url, depth + 1)
        except:
            pass

    crawl(url, 0)
    return sorted(hosts)

def check_port(host, port, timeout=1):
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        return True
    except:
        return False

def check_http(host):
    try:
        resp = requests.get(f"http://{host}", timeout=3)
        return resp.status_code == 200, resp.headers
    except:
        return False, {}

def check_https(host):
    try:
        resp = requests.get(f"https://{host}", timeout=3, verify=False)
        return resp.status_code == 200, resp.headers
    except:
        return False, {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/extract_hosts', methods=['POST'])
def api_extract_hosts():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'error': 'Missing URL'}), 400
    hosts = deep_crawl(url, max_depth=3)
    return jsonify({'hosts': hosts})

@app.route('/api/check_port', methods=['POST'])
def api_check_port():
    data = request.get_json()
    host = data.get('host')
    port = data.get('port')
    if not host or not port:
        return jsonify({'error': 'Missing host or port'}), 400
    is_open = check_port(host, port)
    return jsonify({'open': is_open})

@app.route('/api/check_response', methods=['POST'])
def api_check_response():
    data = request.get_json()
    host = data.get('host')
    port = data.get('port')
    if not host or not port:
        return jsonify({'error': 'Missing host or port'}), 400
    if port == 80:
        success, headers = check_http(host)
    elif port == 443:
        success, headers = check_https(host)
    else:
        success, headers = False, {}
    headers_dict = {k: v for k, v in headers.items()} if headers else {}
    return jsonify({'success': success, 'headers': headers_dict})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
