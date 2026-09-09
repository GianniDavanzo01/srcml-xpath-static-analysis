import flask

def create_response(content_type):
    """Creates a response with the specified content type.
    
    Args:
      content_type: The content type of the response.
      
    Returns:
      A flask.Response object.
    """
    
    # Create a response object.
    response = flask.Response()
    
    # Set the content type of the response.
    response.headers["Content-Type"] = content_type
    
    # Return the response object.
    return response

app = flask.Flask(__name__)

@app.route("/")
def index():
    # Create a response with the text/plain content type.
    response = create_response("text/plain")
    
    # Set the body of the response.
    response.set_data("This is a text/plain response.")
    
    # Return the response object.
    return response

if __name__ == "__main__":
    app.run(debug=True)