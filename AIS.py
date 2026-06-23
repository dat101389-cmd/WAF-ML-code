import datetime
import logging
from flask import Flask, request, Response
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from urllib.parse import unquote
import requests

app = Flask(__name__)

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

BACKEND_HOST = "http://127.0.0.1"
BACKEND_PORT = "80"  
BACKEND_URL = f"{BACKEND_HOST}:{BACKEND_PORT}"

dashboard = {
    "total_requests": 0,
    "allowed_requests": 0,
    "blocked_requests": 0,
    "sqli_count": 0,
    "xss_count": 0,
    "anomaly_count": 0
}

def print_dashboard():
    print("\n" + "="*50)
    print(f"    [ML-WAF ACTIVE DASHBOARD] - {datetime.datetime.now().strftime('%H:%M:%S')}")
    print("="*50)
    print(f"  Tổng số Request đã xử lý: {dashboard['total_requests']}")
    print(f"  Hợp lệ (Allowed):        {dashboard['allowed_requests']}")
    print(f"  Bị chặn (Blocked):       {dashboard['blocked_requests']}")
    print("-"*50)
    print("    THỐNG KÊ CHI TIẾT CUỘC TẤN CÔNG:")
    print(f"    [!] SQL Injection:   {dashboard['sqli_count']} request")
    print(f"    [!] XSS Attack:      {dashboard['xss_count']} request")
    print(f"    [!] Bất thường/Khác: {dashboard['anomaly_count']} request")
    print("="*50 + "\n")

print("-> [1/4] Đang khởi tạo dữ liệu mẫu...")
raw_normal = [
    "index.php", "login.php", "submit=Submit", "username=admin&password=password",
    "id=1", "id=5", "search=ao+thun+nam", "page=home", "user_id=10", "main.css",
    "bootstrap.min.js", "logo.png", "index.php?page=products", "view=item&id=99"
]

raw_attack = [
    "id=1' OR '1'='1", "id=1' UNION SELECT NULL, password FROM users --",
    "username=admin' --", "id=1; DROP TABLE users", "1' or '1'='1", "admin'--",
    "search=<script>alert(1)</script>", "name=<img src=x onerror=alert('hack')>",
    "../../../../etc/passwd", "&& dir c:\\", "UNION SELECT", "SELECT+first_name"
]

normal_queries = []
attack_queries = []
for i in range(25):  
    for item in raw_normal: normal_queries.append(f"{item}&rand_id={i * 7}")
    for item in raw_attack: attack_queries.append(f"{item}&variant={i * 3}")

X = normal_queries + attack_queries
y = [0] * len(normal_queries) + [1] * len(attack_queries)


X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)


vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(1, 5))
X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

print("-> [3/4] Đang huấn luyện mô hình Logistic Regression...")
model = LogisticRegression(C=5.0, max_iter=500)
model.fit(X_train_tfidf, y_train)

y_pred = model.predict(X_test_tfidf)
print("\n" + "-"*50)
print(f"  AI MODEL ACCURACY: {accuracy_score(y_test, y_pred)*100:.2f}%")
print("-"*50)
print(classification_report(y_test, y_pred, target_names=["Hợp lệ (0)", "Tấn công (1)"]))
print("-"*50 + "\n")

print("-> [4/4] ML-WAF đã sẵn sàng tại: http://127.0.0.1:5000")
print_dashboard()

def check_rule_anomaly(path, query_string, post_data):
    q = str(query_string or "")
    p = str(post_data or "")
    data_to_check = (q + " " + p).lower()

    if len(q) > 500 or len(p) > 1000:
        return True, "Vượt quá độ dài dữ liệu định mức an toàn", "anomaly"

    if any(pattern in data_to_check for pattern in ["../", "passwd", "etc/"]):
        return True, "Dấu hiệu truy cập tệp tin hệ thống trái phép (Path Traversal)", "anomaly"

    return False, "", ""

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    dashboard["total_requests"] += 1
    try:
        query_string = request.query_string.decode('utf-8', errors='ignore')
        post_data = request.get_data().decode('utf-8', errors='ignore')
        
        decoded_query = unquote(query_string)
        decoded_post = unquote(post_data)
        full_payload = f"{path}?{decoded_query} {decoded_post}".strip()
        
        is_blocked = False
        reason = ""
        attack_type = "anomaly"
        
        payload_tfidf = vectorizer.transform([full_payload])
        probability = model.predict_proba(payload_tfidf)[0][1] * 100
        
        if probability >= 85.0:
            is_blocked = True
            if any(k in full_payload.lower() for k in ["script", "alert", "onerror", "svg", "javascript"]):
                attack_type = "xss"
                reason = "Mô hình ML phát hiện độc hại -> Tầng lọc gán nhãn: Tấn công XSS"
            elif any(k in full_payload.lower() for k in ["select", "union", "'", "--", "drop"]):
                attack_type = "sqli"
                reason = "Mô hình ML phát hiện độc hại -> Tầng lọc gán nhãn: Tấn công SQL Injection"
            else:
                attack_type = "anomaly"
                reason = "Mô hình ML phát hiện cấu trúc chuỗi độc hại không xác định"
        else:
            is_anomaly, rule_reason, rule_attack_type = check_rule_anomaly(path, decoded_query, decoded_post)
            if is_anomaly:
                is_blocked = True
                reason = rule_reason
                attack_type = rule_attack_type
                probability = 99.9 

        if is_blocked:
            dashboard["blocked_requests"] += 1
            dashboard[f"{attack_type}_count"] += 1
            print_dashboard()
            return f"""
            <div style='color:red; text-align:center; margin-top:80px; font-family:Arial; background-color:#fff5f5; padding:30px; border:2px solid red; max-width:650px; margin-left:auto; margin-right:auto; border-radius:10px;'>
                <h1 style='font-size:36px;'>[!] 403 Forbidden</h1>
                <h2>ML-WAF ĐÃ CHẶN TRUY CẬP</h2>
                <hr>
                <p style='text-align:left;'><strong>Cơ chế:</strong> Machine Learning + Kiểm tra luật bất thường</p>
                <p style='text-align:left;'><strong>Lý do:</strong> <span style='color:purple; font-weight:bold;'>{reason}</span></p>
                <p style='text-align:left;'><strong>Độ rủi ro:</strong> <span style='color:red; font-weight:bold;'>{probability:.1f}%</span></p>
            </div>
            """, 403

        dashboard["allowed_requests"] += 1
        print_dashboard()

    except Exception as e:
        dashboard["blocked_requests"] += 1
        dashboard["anomaly_count"] += 1
        print_dashboard()
        return f"[!] 403 Forbidden - Lỗi luồng xử lý", 403

    url = f"{BACKEND_URL}/{path}"
    if request.query_string: url += f"?{query_string}"

    try:
        req_headers = {key: value for (key, value) in request.headers if key.lower() != 'host'}
        resp = requests.request(
            method=request.method, url=url, headers=req_headers,
            data=request.get_data(), cookies=request.cookies, allow_redirects=False
        )
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        return Response(resp.content, resp.status_code, headers)
    except requests.exceptions.ConnectionError:
        return f"<h3>[ML-WAF] Request an toàn nhưng Backend thực tế ({BACKEND_URL}) chưa bật.</h3>", 502

if __name__ == '__main__':
    app.run(port=5000, debug=False)