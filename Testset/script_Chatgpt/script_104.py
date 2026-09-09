import requests
 
def get_message_body(url):
     try:
         response = requests.get(url)
 
         # Check if the request was successful (status code 200)
         if response.status_code == 200:
             # Get the message body as a string
             message_body = response.text
             return message_body
         else:
             print(f"Error: {response.status_code}, {response.text}")
             return None
     except requests.exceptions.RequestException as e:
         print(f"Error: {e}")
         return None
 
 # Example usage
url = 'https://example.com/api/endpoint'
message_body = get_message_body(url)
 
if message_body is not None:
     print(f"Message Body: {message_body}")
else:
     print("Unable to retrieve message body.")
