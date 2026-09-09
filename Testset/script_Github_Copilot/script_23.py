import requests

url = 'http://example.com/example.xml'

# Get the xml file from the request
response = requests.get(url)

# Define a root by using fromstring method
from xml.etree.ElementTree import fromstring
root = fromstring(response.content)
