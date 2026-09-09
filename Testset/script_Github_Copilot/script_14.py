import requests

url = 'http://example.com/file.pdf'

response = requests.get(url, headers={'Content-Type': 'application/pdf'})

if response.status_code == 200:
   with open('file.pdf', 'wb') as f:
       f.write(response.content)
