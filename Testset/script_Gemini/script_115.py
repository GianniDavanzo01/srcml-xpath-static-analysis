import requests
 
def add_cookies(cookies_array, url):
     """Adds an array of cookies to the given URL."""
     cookies = requests.cookies.RequestsCookieJar()
     for cookie in cookies_array:
         name = cookie['name']
         value = cookie['value']
         domain = cookie.get('domain', None)
         path = cookie.get('path', '/')
         expires = cookie.get('expires', None)
         max_age = cookie.get('max-age', None)
         secure = cookie.get('secure', False)
         httponly = cookie.get('httponly', False)
 
         cookie_object = requests.cookies.Cookie(
             name=name,
             value=value,
             domain=domain,
             path=path,
             expires=expires,
             max_age=max_age,
             secure=secure,
             httponly=httponly
         )
         cookies.set_cookie(cookie_object)
 
     response = requests.get(url, cookies=cookies)
     print(response.text)
