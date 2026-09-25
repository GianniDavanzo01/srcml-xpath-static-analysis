import urllib.request

url = 'http://www.example.com/file.txt'

with urllib.request.urlopen(url) as response:
  file_parameter = response.read()

print(file_parameter)
