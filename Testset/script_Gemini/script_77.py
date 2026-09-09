import http.cookies 
  
def create_response(cookies): 
   # Create a response. 
   response = http.cookies.SimpleCookie() 
  
   # Set the cookies. 
   for name, value in cookies.items(): 
     response[name] = value 
  
   # Return the response. 
   return response 
  
  
cookies = {'name': 'value', 'age': '30'} 
  
response = create_response(cookies) 
  
print(response)
