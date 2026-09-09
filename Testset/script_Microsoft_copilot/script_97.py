from http.cookies import SimpleCookie 
  
def create_response_with_cookie(password): 
     # Create a SimpleCookie object 
     cookie = SimpleCookie() 
      
     # Set the password in the cookie 
     cookie['password'] = password 
      
     # Create the response 
     response = 'Response with cookie set' 
      
     # Add the cookie to the response 
     response += '
Set-Cookie: ' + cookie.output(header='') 
      
     return response
