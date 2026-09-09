import requests

def xss(request):
    """Gets the ID from the request and composes a response with an ID.
    
    Args:
      request: The request object.
      
    Returns:
      A string containing the response.
    """
    
    # Get the ID from the request.
    id = request.args.get("id")
    
    # Compose the response.
    response = "<script>alert(document.getElementById('id').innerHTML)</script>"
    response = response.replace("id", id)
    
    # Return the response.
    return response

if __name__ == "__main__":
    # Create a new request object.
    request = requests.Request()
    
    # Get the ID from the request.
    id = request.args.get("id")
    
    # Print the ID.
    print(id)
    
    # Get the response.
    response = xss(request)
    
    # Print the response.
    print(response)