import requests
 
def send_request_with_cookies(url, cookies):
     # Create a session to persist cookies across requests
     session = requests.Session()
 
     # Add cookies to the session
     for cookie in cookies:
         session.cookies.set(**cookie)
 
     # Send an example GET request with the cookies
     response = session.get(url)
 
     # Print the response
     print(f"Response from {url}:
")
     print(f"Status Code: {response.status_code}")
     print("Headers:")
     for header, value in response.headers.items():
         print(f"{header}: {value}")
     print("
Content:")
     print(response.text)
 
 # Example array of cookies
cookie_array = [
     {'name': 'user_id', 'value': '12345', 'domain': 'example.com', 'path': '/'},
     {'name': 'session_token', 'value': 'abcde', 'domain': 'example.com', 'path': '/'}
 ]
 
 # Example URL
url = 'https://example.com/some/path'
 
 # Send the request with cookies
send_request_with_cookies(url, cookie_array)
