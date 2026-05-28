import sqlite3
import json
import os
import re
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

DB_PATH = "logs.db"
HOST = "127.0.0.1"
PORT = 8000


# ==================== БАЗА ДАННЫХ ====================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (id INTEGER PRIMARY KEY, ip TEXT, date TEXT, method TEXT, 
                  url TEXT, status INTEGER, size INTEGER, user_agent TEXT)''')
    c.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'admin123')")
    conn.commit()
    conn.close()


# ==================== ПАРСЕР ЛОГОВ APACHE ====================
def parse_apache_log(filepath):
    pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<date>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<url>\S+) \S+" '
        r'(?P<status>\d+) (?P<size>\d+) '
        r'"[^"]*" "(?P<user_agent>[^"]*)"'
    )

    logs = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = pattern.match(line.strip())
                if match:
                    data = match.groupdict()
                    try:
                        dt = datetime.strptime(data['date'], '%d/%b/%Y:%H:%M:%S %z')
                        data['date'] = dt.isoformat()
                    except:
                        data['date'] = datetime.now().isoformat()
                    data['size'] = int(data['size']) if data['size'].isdigit() else 0
                    data['status'] = int(data['status'])
                    logs.append(data)
    except Exception as e:
        print(f"Ошибка чтения файла: {e}")
    return logs


def save_logs_to_db(logs):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    for log in logs:
        c.execute('''INSERT INTO logs (ip, date, method, url, status, size, user_agent)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (log['ip'], log['date'], log['method'], log['url'],
                   log['status'], log['size'], log['user_agent']))
    conn.commit()
    conn.close()


# ==================== HTML СТРАНИЦА ====================
HTML = '''<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Log Analyzer</title>
    <style>
        body { font-family: Arial; background: #1e1e2f; color: #fff; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        input, select, button { padding: 8px; margin: 5px; border-radius: 6px; border: none; }
        button { background: #4CAF50; color: white; cursor: pointer; }
        .filters { background: #2d2d44; padding: 15px; border-radius: 10px; margin: 15px 0; }
        pre { background: #2d2d44; padding: 15px; border-radius: 10px; overflow: auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #444; }
        .progress { background: #333; border-radius: 10px; margin: 10px 0; height: 30px; position: relative; }
        .progress-fill { background: #4CAF50; height: 100%; width: 0%; border-radius: 10px; }
        .progress-text { position: absolute; width: 100%; text-align: center; line-height: 30px; }
        .hidden { display: none; }
        .toolbar { margin: 10px 0; }
    </style>
</head>
<body>
<div class="container">
    <h1>📊 Apache Log Analyzer</h1>

    <div id="authPanel">
        <h2>Авторизация</h2>
        <input type="text" id="username" placeholder="Логин"><br>
        <input type="password" id="password" placeholder="Пароль"><br>
        <button onclick="login()">Войти</button>
    </div>

    <div id="mainPanel" class="hidden">
        <div class="toolbar">
            <button onclick="parseLogs()">🔍 Парсить логи</button>
            <button onclick="loadLogs()">📋 Загрузить логи</button>
        </div>

        <div class="filters">
            <h3>Фильтры</h3>
            <label>IP: <input type="text" id="ipFilter" placeholder="IP адрес"></label>
            <label>Дата с: <input type="datetime-local" id="startDate"></label>
            <label>Дата по: <input type="datetime-local" id="endDate"></label>
            <select id="groupBy">
                <option value="">Без группировки</option>
                <option value="ip">По IP</option>
                <option value="url">По URL</option>
            </select>
            <button onclick="applyFilters()">Применить</button>
        </div>

        <div id="progressBar" class="progress hidden">
            <div class="progress-fill"></div>
            <div class="progress-text">Загрузка...</div>
        </div>

        <div id="urlPanel" class="hidden">
            <h3>URL (выбери)</h3>
            <select id="urlSelect" size="8" style="width:100%"></select>
            <button onclick="showUrlContent()">Показать</button>
        </div>

        <div>
            <h3>Результат</h3>
            <div id="result"></div>
        </div>
    </div>
</div>

<script>
    let token = null;

    async function login() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        const resp = await fetch('/api/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
        });

        if (resp.ok) {
            token = await resp.json();
            document.getElementById('authPanel').style.display = 'none';
            document.getElementById('mainPanel').classList.remove('hidden');
            loadLogs();
        } else {
            alert('Неверный логин или пароль');
        }
    }

    async function parseLogs() {
        showProgress(true);
        try {
            const resp = await fetch('/api/parse', {method: 'POST'});
            const data = await resp.json();
            alert(`Добавлено: ${data.added}`);
            loadLogs();
        } catch(e) { alert(e.message); }
        showProgress(false);
    }

    async function loadLogs() {
        showProgress(true);
        try {
            const filters = getFilters();
            const resp = await fetch('/api/logs', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(filters)
            });
            const data = await resp.json();
            displayResult(data);
        } catch(e) { alert(e.message); }
        showProgress(false);
    }

    function getFilters() {
        return {
            ip: document.getElementById('ipFilter').value,
            start_date: document.getElementById('startDate').value,
            end_date: document.getElementById('endDate').value,
            group_by: document.getElementById('groupBy').value
        };
    }

    function displayResult(data) {
        const resultDiv = document.getElementById('result');
        const urlPanel = document.getElementById('urlPanel');

        if (data.group_by === 'url') {
            let html = '<table><tr><th>URL</th><th>Количество</th></tr>';
            for (let row of data.data) {
                html += `<tr><td>${row.url}</td><td>${row.count}</td></tr>`;
            }
            html += '</table>';
            resultDiv.innerHTML = html;

            const select = document.getElementById('urlSelect');
            select.innerHTML = '';
            for (let row of data.data) {
                let opt = document.createElement('option');
                opt.value = row.url;
                opt.textContent = `${row.url} (${row.count})`;
                select.appendChild(opt);
            }
            urlPanel.classList.remove('hidden');
        } else if (data.group_by === 'ip') {
            let html = '<table><tr><th>IP</th><th>Количество</th><th>Размер (байт)</th></tr>';
            for (let row of data.data) {
                html += `<tr><td>${row.ip}</td><td>${row.count}</td><td>${row.total_size || 0}</td></tr>`;
            }
            html += '</table>';
            resultDiv.innerHTML = html;
            urlPanel.classList.add('hidden');
        } else {
            if (data.data.length === 0) {
                resultDiv.innerHTML = '<p>Нет данных</p>';
            } else {
                let html = '<table><tr><th>IP</th><th>Дата</th><th>Метод</th><th>URL</th><th>Статус</th><th>Размер</th></tr>';
                for (let row of data.data) {
                    html += `<tr><td>${row.ip}</td><td>${row.date}</td><td>${row.method}</td><td>${row.url}</td><td>${row.status}</td><td>${row.size}</td></tr>`;
                }
                html += '</table>';
                resultDiv.innerHTML = html;
            }
            urlPanel.classList.add('hidden');
        }
    }

    function showUrlContent() {
        const url = document.getElementById('urlSelect').value;
        document.getElementById('result').innerHTML = `<pre>Выбран URL: ${url}\\n\\nЗдесь можно вывести детали по этому URL</pre>`;
    }

    function applyFilters() { loadLogs(); }

    function showProgress(show) {
        const bar = document.getElementById('progressBar');
        if (show) bar.classList.remove('hidden');
        else bar.classList.add('hidden');
    }
</script>
</body>
</html>'''


# ==================== HTTP СЕРВЕР ====================
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(HTML.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')

        if self.path == '/api/login':
            data = json.loads(body)
            if data.get('username') == 'admin' and data.get('password') == 'admin123':
                self.send_json({'status': 'ok', 'token': 'xxx'})
            else:
                self.send_error_json(401, 'Unauthorized')

        elif self.path == '/api/parse':
            logs_dir = os.path.join(os.path.dirname(__file__), 'logs')
            if not os.path.exists(logs_dir):
                os.makedirs(logs_dir)
            log_files = [f for f in os.listdir(logs_dir) if f.startswith('access') and f.endswith('.log')]
            total_added = 0
            for log_file in log_files:
                logs = parse_apache_log(os.path.join(logs_dir, log_file))
                save_logs_to_db(logs)
                total_added += len(logs)
            self.send_json({'status': 'ok', 'added': total_added})

        elif self.path == '/api/logs':
            filters = json.loads(body)
            group_by = filters.get('group_by', '')
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()

            if group_by == 'ip':
                query = "SELECT ip, COUNT(*) as count, SUM(size) as total_size FROM logs WHERE 1=1"
                params = []
                if filters.get('ip'):
                    query += " AND ip = ?"
                    params.append(filters['ip'])
                if filters.get('start_date'):
                    query += " AND date >= ?"
                    params.append(filters['start_date'])
                if filters.get('end_date'):
                    query += " AND date <= ?"
                    params.append(filters['end_date'])
                query += " GROUP BY ip"
                c.execute(query, params)
                data = [dict(row) for row in c.fetchall()]
                conn.close()
                self.send_json({'status': 'ok', 'data': data, 'group_by': 'ip'})
            elif group_by == 'url':
                c.execute("SELECT url, COUNT(*) as count FROM logs GROUP BY url ORDER BY count DESC LIMIT 50")
                data = [dict(row) for row in c.fetchall()]
                conn.close()
                self.send_json({'status': 'ok', 'data': data, 'group_by': 'url'})
            else:
                query = "SELECT * FROM logs WHERE 1=1"
                params = []
                if filters.get('ip'):
                    query += " AND ip = ?"
                    params.append(filters['ip'])
                if filters.get('start_date'):
                    query += " AND date >= ?"
                    params.append(filters['start_date'])
                if filters.get('end_date'):
                    query += " AND date <= ?"
                    params.append(filters['end_date'])
                c.execute(query, params)
                data = [dict(row) for row in c.fetchall()]
                conn.close()
                self.send_json({'status': 'ok', 'data': data, 'group_by': ''})

        else:
            self.send_error_json(404, 'Not Found')

    def send_json(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def send_error_json(self, code, msg):
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'error': msg}).encode('utf-8'))


# ==================== ЗАПУСК ====================
if __name__ == "__main__":
    init_db()
    os.makedirs("logs", exist_ok=True)
    print(f"✅ Сервер запущен: http://{HOST}:{PORT}")
    print(f"🔐 Логин: admin, Пароль: admin123")
    print(f"📁 Положи файлы логов в папку 'logs' (формат: access*.log)")
    print("🛑 Нажми Ctrl+C для остановки")
    server = HTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 Сервер остановлен")