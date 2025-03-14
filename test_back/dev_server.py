from flask import Flask, request, jsonify, render_template_string
import logging
import os
import traceback
import time
import json
from datetime import datetime

# 로깅 설정 (개발 서버는 상세 로깅)
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - [DEV] %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.debug = True  # 디버그 모드 활성화

# 요청 로그를 저장할 리스트
request_logs = []
attack_logs = []

# 요청 로깅 미들웨어
@app.before_request
def log_request_info():
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 요청 정보 수집
    log_data = {
        'timestamp': timestamp,
        'method': request.method,
        'path': request.path,
        'ip': request.remote_addr,
        'headers': dict(request.headers),
        'args': dict(request.args),
        'form': dict(request.form),
        'json': request.json if request.is_json else None,
    }
    
    # 공격 의심 패턴 체크
    is_attack = False
    attack_type = []
    
    # SQL 인젝션 체크
    sql_patterns = ["'", ";", "--", "/*", "*/", "UNION", "SELECT", "DROP", "DELETE", "UPDATE", "INSERT"]
    for pattern in sql_patterns:
        request_form_str = str(request.form).lower()
        request_args_str = str(request.args).lower()
        
        if pattern.lower() in request_form_str or pattern.lower() in request_args_str:
            is_attack = True
            attack_type.append("SQL Injection")
            break
    
    # XSS 체크
    xss_patterns = ["<script>", "javascript:", "onclick", "onerror", "onload", "alert(", "eval("]
    for pattern in xss_patterns:
        request_form_str = str(request.form).lower()
        request_args_str = str(request.args).lower()
        
        if pattern.lower() in request_form_str or pattern.lower() in request_args_str:
            is_attack = True
            if "XSS" not in attack_type:
                attack_type.append("XSS")
            break
    
    # 경로 조작 체크
    if "../" in request.path or "..%2f" in request.path:
        is_attack = True
        attack_type.append("Path Traversal")
    
    # 공격 의심 정보 추가
    log_data['is_attack'] = is_attack
    log_data['attack_type'] = attack_type if is_attack else None
    
    # 로그 저장
    request_logs.append(log_data)
    if is_attack:
        attack_logs.append(log_data)
        logger.warning(f"공격 의심: {attack_type} - {request.path}")
    
    # 로그 크기 제한 (최근 100개만 유지)
    if len(request_logs) > 100:
        request_logs.pop(0)
    if len(attack_logs) > 50:
        attack_logs.pop(0)
    
    logger.debug(f"{timestamp} - {request.method} {request.path}")
    logger.debug(f"Headers: {request.headers}")
    logger.debug(f"Body: {request.get_data()}")

# 오류 핸들러
@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f'예외 발생: {str(e)}')
    logger.error(traceback.format_exc())
    return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

# 메인 페이지
@app.route('/')
def index():
    return render_template_string("""
    <html>
    <head>
        <title>개발 서버 (디버깅)</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
            h1 { color: #333; }
            form { margin-bottom: 20px; }
            input, button { padding: 8px; margin: 5px 0; }
            .nav { margin-top: 20px; }
            .nav a { margin-right: 15px; text-decoration: none; color: #0066cc; }
        </style>
    </head>
    <body>
        <h1>개발 서버 (디버깅 모드)</h1>
        <form action="/login" method="post">
            <input name="username" placeholder="사용자명">
            <input name="password" placeholder="비밀번호" type="password">
            <button>로그인</button>
        </form>
        <div class="nav">
            <a href="/comments">댓글 보기</a>
            <a href="/logs">로그 대시보드</a>
            <a href="/attack-logs">공격 로그</a>
        </div>
    </body>
    </html>
    """)

# 취약한 로그인 엔드포인트 (운영 서버와 동일하지만 로깅 강화)
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # SQL 쿼리 시뮬레이션 (개발 서버도 동일한 취약점 포함)
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    
    # 디버깅용 상세 로깅
    logger.debug(f"로그인 요청 파라미터: username={username}, password={password}")
    logger.debug(f"생성된 SQL 쿼리: {query}")
    
    # SQL 인젝션 탐지 시도 (간단한 체크)
    if "'" in username or "'" in password:
        logger.warning(f"SQL 인젝션 공격 의심: {username} / {password}")
    
    # 로그인 응답
    return jsonify({
        "status": "success", 
        "query": query,
        "debug_info": {
            "username_length": len(username) if username else 0,
            "has_special_chars": any(c in username for c in "'\"\\;") if username else False
        }
    })

# XSS 취약점이 있는 댓글 시스템 (운영 서버와 동일하게 취약)
@app.route('/comments', methods=['GET', 'POST'])
def comments():
    if request.method == 'POST':
        comment = request.form.get('comment', '')
        
        # 디버깅용 로깅
        logger.debug(f"댓글 내용: {comment}")
        
        # XSS 의심 패턴 체크
        if '<script>' in comment.lower():
            logger.warning(f"XSS 공격 의심: {comment}")
        
        # 댓글 추가 (필터링 없음 - XSS 취약)
        return render_template_string("<p>댓글이 추가되었습니다: " + comment + "</p>")
    
    # 댓글 목록
    return render_template_string("<h1>댓글</h1><form method='post'><input name='comment'><button>추가</button></form>")

# 로그 대시보드 페이지 (모든 요청 로그 표시)
@app.route('/logs')
def view_logs():
    return render_template_string("""
    <html>
    <head>
        <title>요청 로그 대시보드</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
            h1 { color: #333; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background-color: #f2f2f2; }
            tr:hover { background-color: #f5f5f5; }
            .attack { background-color: #ffcccc; }
            .details-btn { cursor: pointer; color: blue; text-decoration: underline; }
            .details { display: none; white-space: pre-wrap; font-family: monospace; }
            .nav { margin: 20px 0; }
            .nav a { margin-right: 15px; text-decoration: none; color: #0066cc; }
            .reload { float: right; }
        </style>
        <script>
            function toggleDetails(id) {
                var details = document.getElementById('details-' + id);
                if (details.style.display === 'none') {
                    details.style.display = 'block';
                } else {
                    details.style.display = 'none';
                }
            }
            
            function refreshPage() {
                location.reload();
            }
            
            // 10초마다 자동 새로고침
            setTimeout(refreshPage, 10000);
        </script>
    </head>
    <body>
        <h1>요청 로그 대시보드</h1>
        <div class="nav">
            <a href="/">홈</a>
            <a href="/attack-logs">공격 로그만 보기</a>
            <button class="reload" onclick="refreshPage()">새로고침</button>
        </div>
        <table>
            <tr>
                <th>시간</th>
                <th>메소드</th>
                <th>경로</th>
                <th>IP</th>
                <th>공격 여부</th>
                <th>상세</th>
            </tr>
            {% for i, log in enumerate(reversed(logs)) %}
                <tr class="{{ 'attack' if log.get('is_attack') else '' }}">
                    <td>{{ log.get('timestamp') }}</td>
                    <td>{{ log.get('method') }}</td>
                    <td>{{ log.get('path') }}</td>
                    <td>{{ log.get('ip') }}</td>
                    <td>
                        {% if log.get('is_attack') %}
                            <strong>⚠️ {{ ', '.join(log.get('attack_type', [])) }}</strong>
                        {% else %}
                            정상
                        {% endif %}
                    </td>
                    <td><span class="details-btn" onclick="toggleDetails({{ i }})">상세 보기</span></td>
                </tr>
                <tr>
                    <td colspan="6">
                        <div id="details-{{ i }}" class="details">{{ json.dumps(log, indent=2) }}</div>
                    </td>
                </tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """, logs=request_logs, enumerate=enumerate, json=json)

# 공격 로그만 표시하는 페이지
@app.route('/attack-logs')
def view_attack_logs():
    return render_template_string("""
    <html>
    <head>
        <title>공격 의심 로그</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
            h1 { color: #333; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background-color: #f2f2f2; }
            tr:hover { background-color: #f5f5f5; }
            .sql-injection { background-color: #ffcccc; }
            .xss { background-color: #ccffcc; }
            .path-traversal { background-color: #ccccff; }
            .details-btn { cursor: pointer; color: blue; text-decoration: underline; }
            .details { display: none; white-space: pre-wrap; font-family: monospace; }
            .nav { margin: 20px 0; }
            .nav a { margin-right: 15px; text-decoration: none; color: #0066cc; }
            .reload { float: right; }
        </style>
        <script>
            function toggleDetails(id) {
                var details = document.getElementById('attack-details-' + id);
                if (details.style.display === 'none') {
                    details.style.display = 'block';
                } else {
                    details.style.display = 'none';
                }
            }
            
            function refreshPage() {
                location.reload();
            }
            
            // 5초마다 자동 새로고침
            setTimeout(refreshPage, 5000);
        </script>
    </head>
    <body>
        <h1>공격 의심 로그</h1>
        <div class="nav">
            <a href="/">홈</a>
            <a href="/logs">모든 로그 보기</a>
            <button class="reload" onclick="refreshPage()">새로고침</button>
        </div>
        
        {% if logs %}
            <table>
                <tr>
                    <th>시간</th>
                    <th>공격 유형</th>
                    <th>메소드</th>
                    <th>경로</th>
                    <th>IP</th>
                    <th>상세</th>
                </tr>
                {% for i, log in enumerate(reversed(logs)) %}
                    <tr class="{{ (log.get('attack_type', [''])[0].lower().replace(' ', '-') if log.get('attack_type') and log.get('attack_type')[0] else '') }}">
                        <td>{{ log.get('timestamp') }}</td>
                        <td><strong>{{ ', '.join(log.get('attack_type', [])) }}</strong></td>
                        <td>{{ log.get('method') }}</td>
                        <td>{{ log.get('path') }}</td>
                        <td>{{ log.get('ip') }}</td>
                        <td><span class="details-btn" onclick="toggleDetails({{ i }})">상세 보기</span></td>
                    </tr>
                    <tr>
                        <td colspan="6">
                            <div id="attack-details-{{ i }}" class="details">{{ json.dumps(log, indent=2) }}</div>
                        </td>
                    </tr>
                {% endfor %}
            </table>
        {% else %}
            <p>아직 공격 의심 로그가 없습니다.</p>
        {% endif %}
    </body>
    </html>
    """, logs=attack_logs, enumerate=enumerate, json=json)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8081))
    app.run(host='0.0.0.0', port=port)