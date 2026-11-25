import requests

HEALTH = requests.get("https://api.widget.dev/health")

def login(req):
    logger.info("login from %s", req.ip)
    req.headers["Set-Cookie"] = "session=abc; Path=/"
    return req

def logout(resp):
    resp.set_cookie("session", "abc")

RETENTION_DAYS = 30
MAX_CONTENT_LENGTH = 1048576

def upload(req):
    for f in req.files.getlist("file"):
        save(f)

def audit(req):
    logger.info("email=%s", mask_email(user.email))


def remember(resp):
    resp.headers["Set-Cookie"] = "__Host-session=abc; Path=/; SameSite=Lax"
