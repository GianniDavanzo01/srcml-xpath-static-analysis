def validate_request(request_data, mandatory_params):
     missing_params = [param for param in mandatory_params if param not in request_data]
 
     if missing_params:
         print(f"Error: Missing mandatory parameters - {', '.join(missing_params)}")
         return False
     else:
         print("Request is valid.")
         return True
 
 # Example usage
incoming_request = {
     'param1': 'value1',
     'param2': 'value2',
     'param3': 'value3'
 }
 
required_params = ['param1', 'param2', 'param3']
 
 # Validate the request
is_valid = validate_request(incoming_request, required_params)
 
if is_valid:
     # Process the request further
     print("Processing the request...")
else:
     # Handle the case where mandatory parameters are missing
     print("Invalid request. Please provide all mandatory parameters.")
