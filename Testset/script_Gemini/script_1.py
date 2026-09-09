import flask

def get_name():
    """Gets the name parameter from the URL and opens the file names/name.
    
    Returns:
      A file object.
    """
    
    # Import the request module from Flask.
    request = flask.request
    
    # Get the name parameter from the URL.
    name = request.args.get("name")
    
    # If the name parameter is not present, return None.
    if name is None:
        return None
    
    # Open the file names/name.
    file_object = open("names/" + name, "r")
    
    # Return the file object.
    return file_object