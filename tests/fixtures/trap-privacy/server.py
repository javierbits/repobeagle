def login(resp):
    resp.headers["Set-Cookie"] = "session=abc; Path=/"
    return resp
