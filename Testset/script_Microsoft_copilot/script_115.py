from http.cookies import SimpleCookie
 
class CookieHandler:
     def __init__(self):
         self.cookie = SimpleCookie()
 
     def add_cookies(self, cookie_array):
         for cookie in cookie_array:
             self.cookie[cookie[0]] = cookie[1]
 
 # Usage
handler = CookieHandler()
cookies_to_add = [('cookie1', 'value1'), ('cookie2', 'value2')]
handler.add_cookies(cookies_to_add)
print(handler.cookie)
