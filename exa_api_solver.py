"""
Exa 协议注册机
仅走 curl_cffi + Turnstile Solver + OTP 协议流。
"""
import base64
import os
import re
import threading
import time
from urllib.parse import parse_qs, quote, urljoin, urlparse

from config import EMAIL_CODE_TIMEOUT, REQUEST_PROXIES
from mail_provider import get_email_code
from turnstile_solver import solve_turnstile

try:
    from curl_cffi import requests as http_requests
    _HTTP_BACKEND = "curl_cffi"
except Exception:
    import requests as http_requests
    _HTTP_BACKEND = "requests"

_HERE = os.path.dirname(os.path.abspath(__file__))
_SAVE_FILE = os.path.join(_HERE, "exa-keys.txt")
_SAVE_LOCK = threading.Lock()

_EXA_SITEKEY = "0x4AAAAAADSpJWQOnICEKAwx"
_EXA_PROMO_CODES = ("EXA50API", "EXA50BUILDCLUB")
_TURNSTILE_ACTION = "auth_signin"
_AUTH_BASE = "https://auth.exa.ai"
_AUTH_URL = "https://auth.exa.ai/?callbackUrl=https%3A%2F%2Fdashboard.exa.ai%2F"
_DASHBOARD_BASE = "https://dashboard.exa.ai"
_CALLBACK_URL = "https://dashboard.exa.ai/"

_SESSION_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
}


# ──────────────────────────────────────────────
# Dashboard API（纯 requests）
# ──────────────────────────────────────────────


def _new_http_session():
    if _HTTP_BACKEND == "curl_cffi":
        session = http_requests.Session(impersonate="chrome131")
    else:
        session = http_requests.Session()
    if REQUEST_PROXIES:
        session.proxies.update(REQUEST_PROXIES)
    return session


def _http_request(method, url, **kwargs):
    if _HTTP_BACKEND == "curl_cffi":
        kwargs.setdefault("impersonate", "chrome131")
    if REQUEST_PROXIES:
        kwargs.setdefault("proxies", REQUEST_PROXIES)
    return http_requests.request(method, url, **kwargs)


def _encode_turnstile_cdata(callback_url=_CALLBACK_URL):
    encoded = quote(callback_url, safe="-_.!~*'()")
    return (
        base64.b64encode(encoded.encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
        .replace("+", "-")
        .replace("/", "_")
    )[:255]


def _build_otp_callback_token(hashed_otp, raw_otp):
    return f"{hashed_otp}:{raw_otp}"


def _extract_auth_error_from_location(location):
    if not location:
        return None
    query = parse_qs(urlparse(location).query)
    values = query.get("error")
    return values[0] if values else None


def _dash_req(session, method, path, **kw):
    return session.request(method, f"{_DASHBOARD_BASE}{path}", timeout=kw.pop("timeout", 15), **kw)


# ──────────────────────────────────────────────
# Auth API（curl_cffi + Turnstile Solver）
# ──────────────────────────────────────────────

def _create_auth_session():
    session = _new_http_session()
    session.headers.update(_SESSION_HEADERS)
    try:
        session.get(_AUTH_URL, timeout=15)
    except Exception:
        pass
    return session


def _get_csrf_token(session):
    response = session.get(f"{_AUTH_BASE}/api/auth/csrf", timeout=15)
    response.raise_for_status()
    return response.json()["csrfToken"]


def _solve_auth_turnstile(callback_url=_CALLBACK_URL, retries=3):
    cdata = _encode_turnstile_cdata(callback_url)
    for attempt in range(1, retries + 1):
        print(f"🔐 解决 Turnstile ({attempt}/{retries})...")
        token = solve_turnstile(
            _AUTH_URL,
            _EXA_SITEKEY,
            action=_TURNSTILE_ACTION,
            cdata=cdata,
            timeout=60,
        )
        if token:
            return token
        if attempt < retries:
            time.sleep(2)
    return None


def _verify_turnstile(session, token, email, callback_url=_CALLBACK_URL):
    response = session.post(
        f"{_AUTH_BASE}/api/auth/verify-turnstile",
        json={
            "token": token,
            "provider": "email",
            "email": email.lower(),
            "callbackUrl": callback_url,
            "fallbackReason": None,
        },
        timeout=15,
    )

    try:
        payload = response.json()
    except Exception:
        payload = {}

    if response.status_code == 200 and payload.get("success") is True:
        print("✅ Turnstile 验证通过")
        return True

    preview = (payload.get("error") or response.text or "").strip()[:200]
    print(f"❌ Turnstile 验证失败: HTTP {response.status_code}")
    if preview:
        print(f"   响应: {preview}")
    return False


def _send_verification_email(session, email, csrf_token, callback_url=_CALLBACK_URL):
    token = _solve_auth_turnstile(callback_url=callback_url)
    if not token:
        print("❌ 无法获取 Turnstile token")
        return False

    if not _verify_turnstile(session, token, email, callback_url=callback_url):
        return False

    response = session.post(
        f"{_AUTH_BASE}/api/auth/signin/email",
        data={
            "email": email.lower(),
            "csrfToken": csrf_token,
            "callbackUrl": callback_url,
            "json": "true",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=15,
    )

    try:
        payload = response.json()
    except Exception:
        payload = {}

    if response.status_code == 200 and not payload.get("error"):
        print("✅ 验证邮件已发送")
        return True

    preview = (payload.get("error") or response.text or "").strip()[:200]
    print(f"❌ 发送验证邮件失败: HTTP {response.status_code}")
    if preview:
        print(f"   响应: {preview}")
    return False


def _dashboard_session_ready(session, retries=3, delay=2):
    for attempt in range(1, retries + 1):
        try:
            response = _dash_req(session, "GET", "/api/auth/session", timeout=15)
            if response.status_code == 200:
                payload = response.json()
                user_email = (payload.get("user") or {}).get("email")
                if user_email:
                    print(f"✅ Dashboard 已登录: {user_email}")
                    return True
        except Exception:
            pass

        if attempt < retries:
            time.sleep(delay)

    print("⚠️  Dashboard session 尚未就绪")
    return False


def _verify_email_code(session, email, code, callback_url=_CALLBACK_URL):
    response = session.post(
        f"{_AUTH_BASE}/api/verify-otp",
        json={
            "email": email.lower(),
            "otp": code,
            "callbackUrl": callback_url,
        },
        timeout=15,
    )

    try:
        payload = response.json()
    except Exception:
        payload = {}

    if response.status_code != 200:
        preview = (payload.get("error") or response.text or "").strip()[:200]
        print(f"❌ 验证码验证失败: HTTP {response.status_code}")
        if preview:
            print(f"   响应: {preview}")
        return False

    hashed_otp = payload.get("hashedOtp")
    raw_otp = payload.get("rawOtp")
    if not hashed_otp or not raw_otp:
        print("❌ verify-otp 未返回完整 token 数据")
        return False

    callback_token = _build_otp_callback_token(hashed_otp, raw_otp)
    callback_response = session.get(
        f"{_AUTH_BASE}/api/auth/callback/email",
        params={
            "email": payload.get("email", email.lower()),
            "token": callback_token,
            "callbackUrl": callback_url,
        },
        allow_redirects=False,
        timeout=15,
    )

    if callback_response.status_code not in (302, 303):
        preview = (callback_response.text or "").strip()[:200]
        print(f"❌ callback/email 失败: HTTP {callback_response.status_code}")
        if preview:
            print(f"   响应: {preview}")
        return False

    location = callback_response.headers.get("location") or callback_response.headers.get("Location")
    if not location:
        print("❌ callback/email 未返回跳转地址")
        return False

    auth_error = _extract_auth_error_from_location(location)
    if auth_error:
        cookie_error = None
        try:
            cookie_error = session.cookies.get("exa-auth-error-type")
        except Exception:
            cookie_error = None

        if cookie_error == "domain_throttle" or auth_error == "EmailCreateAccount":
            print("❌ Exa 拒绝为该邮箱域名继续创建账号: domain_throttle")
            print("   当前单域名批量注册已触发限制；请更换域名或降低批量速度")
            return "domain_throttle"

        print(f"❌ callback/email 返回认证错误: {auth_error}")
        return auth_error

    session.get(urljoin(_AUTH_BASE, location), allow_redirects=True, timeout=30)
    return _dashboard_session_ready(session)


def _complete_onboarding(session):
    """用 requests 尝试完成 onboarding。"""
    for m, p, b in [
        ("POST", "/api/complete-onboarding", {"hasCompletedNewAiOnboarding": True}),
        ("PATCH", "/api/auth/session", {"hasCompletedNewAiOnboarding": True}),
    ]:
        try:
            r = _dash_req(session, m, p, json=b, timeout=15)
            if r.status_code in (200, 201):
                print("✅ Onboarding 完成")
                return True
        except Exception:
            continue
    return False


def _redeem_promo_code(session, code):
    print(f"🎁 兑换: {code}")
    for m, p, b in [
        ("POST", "/api/redeem", {"code": code}),
        ("POST", "/api/billing/redeem", {"code": code}),
        ("POST", "/api/redeem-code", {"code": code}),
    ]:
        try:
            r = _dash_req(session, m, p, json=b, timeout=15)
            if r.status_code in (200, 201):
                print(f"✅ {code} 已兑换")
                return True
        except Exception:
            continue
    print(f"⚠️  兑换 {code} 失败")
    return False


def _extract_api_key_from_payload(payload):
    for item in payload.get("apiKeys", []):
        if not item.get("enabled", True):
            continue
        key = (item.get("id") or item.get("key") or item.get("apiKey") or "").strip()
        if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", key, re.I):
            print(f"✅ Key: {key[:20]}...")
            return key
    return None


def _get_api_key(session):
    try:
        response = _dash_req(session, "GET", "/api/get-api-keys", timeout=15)
        if response.status_code == 200:
            return _extract_api_key_from_payload(response.json())
    except Exception:
        pass
    return None


def _create_api_key(session):
    create_endpoints = [
        ("POST", "/api/create-api-key", {"name": "auto-generated"}),
        ("POST", "/api/api-keys", {"name": "auto-generated"}),
        ("POST", "/api/get-api-keys", {"name": "auto-generated", "action": "create"}),
    ]

    for method, path, body in create_endpoints:
        try:
            response = _dash_req(session, method, path, json=body, timeout=15)
            if response.status_code not in (200, 201):
                continue
            payload = response.json()
            key = (
                payload.get("id")
                or payload.get("key")
                or payload.get("apiKey")
                or _extract_api_key_from_payload(payload)
            )
            if key and re.match(r"^[0-9a-f-]{36}$", key, re.I):
                print(f"✅ 创建 Key 成功: {key[:20]}...")
                return key
        except Exception:
            continue
    return None


def _get_or_create_api_key(session, retries=3, delay=2):
    for attempt in range(1, retries + 1):
        key = _get_api_key(session)
        if key:
            return key

        if attempt == 1:
            key = _create_api_key(session)
            if key:
                return key

        if attempt < retries:
            print(f"⏳ 等待 {delay} 秒后重试获取 API Key ({attempt}/{retries})...")
            time.sleep(delay)

    print("⚠️  仍未获取到 API Key")
    return None


def verify_api_key(api_key, timeout=30):
    try:
        r = _http_request(
            "POST",
            "https://api.exa.ai/search",
            json={"query": "test", "numResults": 1},
            headers={"x-api-key": api_key, "Content-Type": "application/json"},
            timeout=timeout,
        )
        print(f"🧪 验证: HTTP {r.status_code} {'✅' if r.status_code == 200 else '❌'}")
        return r.status_code == 200
    except Exception:
        return False


def save_account(api_key):
    with _SAVE_LOCK:
        with open(_SAVE_FILE, "a", encoding="utf-8") as f:
            f.write(f"{api_key}\n")

# ──────────────────────────────────────────────
# 主入口
# ──────────────────────────────────────────────

def register_with_api(email, password):
    print(f"🌐 Exa 注册: {email}")

    session = _create_auth_session()
    auth_flow_completed = False
    try:
        csrf_token = _get_csrf_token(session)
        print("✅ CSRF token 已获取")
    except Exception as exc:
        print(f"❌ 获取 CSRF token 失败: {exc}")
        session = None

    api_key = None
    if session and _send_verification_email(session, email, csrf_token):
        code = get_email_code(email, timeout=EMAIL_CODE_TIMEOUT, service="exa")
        verify_result = _verify_email_code(session, email, code) if code else False
        if verify_result == "domain_throttle":
            return None
        if verify_result:
            auth_flow_completed = True
            _complete_onboarding(session)
            for code in _EXA_PROMO_CODES:
                _redeem_promo_code(session, code)
            api_key = _get_or_create_api_key(session)

    if not api_key:
        if auth_flow_completed:
            print("⚠️  协议流已登录，但暂未拿到 API Key")
            return "SUCCESS_NO_KEY"

        print("❌ 协议流认证未完成，且已禁用浏览器回退")
        return None

    if api_key == "SUCCESS_NO_KEY" or not api_key:
        return "SUCCESS_NO_KEY"

    verify_api_key(api_key)
    save_account(api_key)

    print(f"🎉 成功! Key: {api_key}")
    return api_key


if __name__ == "__main__":
    from mail_provider import create_email
    e, p = create_email(service="exa")
    register_with_api(e, p)
