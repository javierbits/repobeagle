import requests

HEALTH = requests.get("https://api.widget.dev/health")

def login(req):
    logger.info("login from %s", req.ip)
    req.headers["Set-Cookie"] = "session=abc; Path=/"
    return req

def logout(resp):
    resp.set_cookie("session", "abc")
