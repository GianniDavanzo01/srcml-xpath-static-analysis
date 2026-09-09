import urllib.parse 
import requests 
  
def get_file_content(url): 
   parsed_url = urllib.parse.urlparse(url) 
   query_params = urllib.parse.parse_qs(parsed_url.query) 
   file_parameter = query_params["file"][0] 
  
   response = requests.get(url) 
  
   if response.status_code == 200: 
     return response.content 
   else: 
     return None 
  
url = "https://example.com/file?file=my_file.txt" 
  
file_content = get_file_content(url) 
  
if file_content is not None: 
   print(file_content) 
else: 
   print("File not found.")
