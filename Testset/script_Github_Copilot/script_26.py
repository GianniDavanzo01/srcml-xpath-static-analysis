import requests
import xml.etree.ElementTree as ET
from flask import Flask

app = Flask(__name__)

@app.route('/')
def get_xml():
   url = 'http://example.com/xml_source'
   response = requests.get(url)
   root = ET.fromstring(response.content)
   return root

if __name__ == '__main__':
   app.run()
