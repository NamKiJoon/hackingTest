from flask import Flask, request, jsonify, render_template_string
import logging
import os

# 로깅 설정
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - [PROD] %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# 메인 페이지
@app.route('/')
def index():
    return render_template_string("""
    <html>
    <head><title>prod</title></head>
    <body>
        <h1>prod</h1>
        <form action="/login" method="post">
            <input name="username" placeholder="사용자명">
            <input name="password" placeholder="비밀번호" type="password">
            <button>로그인</button>
        </form>
        <p><a href="/comments">댓글 보기</a></p>
    </body>
    </html>
    """)

# 취약한 로그인 엔드포인트 (SQL 인젝션에 취약)
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # 취약한 SQL 쿼리 (시뮬레이션)
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    
    # 간단한 로그
    logger.info(f"로그인 시도: {username}")
    
    # 로그인 성공 시뮬레이션
    return jsonify({"status": "success", "query": query})

# XSS 취약점이 있는 댓글 시스템
@app.route('/comments', methods=['GET', 'POST'])
def comments():
    if request.method == 'POST':
        comment = request.form.get('comment', '')
        # 댓글 저장 시뮬레이션 (필터링 없음 - XSS 취약)
        return render_template_string("<p>댓글이 추가되었습니다: " + comment + "</p>")
    
    # 댓글 목록 표시
    return render_template_string("<h1>댓글</h1><form method='post'><input name='comment'><button>추가</button></form>")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)