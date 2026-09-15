def validate_request(request, mandatory_parameters):
     missing_parameters = [param for param in mandatory_parameters if param not in request]
     if missing_parameters:
         return False, f"Missing parameters: {', '.join(missing_parameters)}"
     else:
         return True, "All mandatory parameters are present"
 
 # Usage
request = {
     'param1': 'value1',
     'param2': 'value2',
     # add more parameters as needed
 }
 
mandatory_parameters = ['param1', 'param2', 'param3']
 
is_valid, message = validate_request(request, mandatory_parameters)
print(message)
