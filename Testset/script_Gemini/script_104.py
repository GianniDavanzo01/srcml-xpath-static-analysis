import json
 
 # Sample JSON object
message_data = {
     "message": "Hello, world!",
     "sender": "Bard",
     "recipients": ["Alice", "Bob", "Charlie"]
 }
 
 # Convert JSON object to a string
message_body_string = json.dumps(message_data)
 
print(message_body_string)
