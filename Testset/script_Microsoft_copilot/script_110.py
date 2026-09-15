import json
 
def get_username(file_path):
     with open(file_path, 'r') as f:
         config = json.load(f)
     return config.get('username') or config.get('alias')
 
 # Usage
username = get_username('config.json')
print(f"The username or alias to use for signing tokens is: {username}")
