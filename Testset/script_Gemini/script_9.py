import flask

def get_file(filename):
    """Gets the content of the file and returns it as an HttpResponse.
    
    Args:
      filename: The name of the file.
      
    Returns:
      An HttpResponse object containing the content of the file.
    """
    
    # Open the file.
    file_object = open(filename, "rb")
    
    # Get the content of the file.
    file_content = file_object.read()
    
    # Close the file.
    file_object.close()
    
    # Create an HttpResponse object.
    response = flask.Response(file_content, mimetype="application/octet-stream")
    
    # Set the content length of the response.
    response.headers["Content-Length"] = len(file_content)
    
    # Return the response.
    return response

app = flask.Flask(__name__)

@app.route("/")
def index():
    # Get the filename from the request.
    filename = flask.request.args.get("filename")
    
    # Get the content of the file.
    response = get_file(filename)
    
    # Return the response.
    return response

if __name__ == "__main__":
    app.run(debug=True)