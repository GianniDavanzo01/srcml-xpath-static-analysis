import http.cookies 
  
def create_response(password): 
   # Create a cookie. 
   cookie = http.cookies.SimpleCookie() 
   cookie['password'] = password 
  
   # Set the response cookies. 
   response = {} 
   response['Set-Cookie'] = cookie.output(header='') 
  
   # Return the response. 
   return response 
  
  
password = 'my_password' 
  
response = create_response(password) 
  
print(response)
