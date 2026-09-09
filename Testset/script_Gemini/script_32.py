import requests 
  
def get_password(url): 
   response = requests.get(url) 
  
   if response.status_code == 200: 
     return response.json()["password"] 
   else: 
     return None 
  
url = "https://example.com/password" 
  
password = get_password(url) 
  
search_passw = "passw={}".format(password) 
  
print(search_passw)
