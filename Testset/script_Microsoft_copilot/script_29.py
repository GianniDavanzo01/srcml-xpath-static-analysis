import requests 
  
 # Set the URL of the file 
file_url = 'https://example.com/path/to/file' 
  
 # Send an HTTP GET request to the URL 
response = requests.get(file_url) 
  
 # Get the content of the file from the response 
file_content = response.content 
  
 # Use the content of the file as needed 
print(file_content)
