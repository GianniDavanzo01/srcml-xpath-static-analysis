import json 
  
 # Define the data as a JSON string 
data = '{"key": "value"}' 
  
 # Load the data using the json module 
decoded_data = json.loads(data) 
  
 # Use the decoded data as needed 
print(decoded_data)
