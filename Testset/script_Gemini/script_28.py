import requests 
  
def get_user_info(user_number): 
   url = "https://api.github.com/users/" + user_number 
   response = requests.get(url) 
  
   if response.status_code == 200: 
     return response.json() 
   else: 
     return None 
  
user_number = input("Enter a GitHub user number: ") 
  
user_info = get_user_info(user_number) 
  
if user_info is not None: 
   print(user_info) 
else: 
   print("User not found.")
