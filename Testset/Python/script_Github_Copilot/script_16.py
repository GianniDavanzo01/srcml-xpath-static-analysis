import logging
import requests

url = 'https://www.example.com/data'

try:
   response = requests.get(url)
   data = response.json()
except Exception as e:
   logging.error('Error getting data from request: %s', e)
