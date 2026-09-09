import flask
import os

def get_file(filename):
    """Checks if the file exists in the names folder and sends it to the browser.
    
    Args:
      filename: The name of the file to check.
      
    Returns:
      A file object.
    """
    
    # Check if the file exists in the names folder.
    if not os.path.exists("names/" + filename):
        return None
        
    # Open the file.
    file_object = open("names/" + filename, "rb")
    
    # Send the file to the browser.
    return file_object

app = flask.Flask(__name__)

@app.route("/")
def index():
    # Get the filename from the request.
    filename = flask.request.args.get("filename")
    
    # Get the file object.
    file_object = get_file(filename)
    
    # If the file object is None, return a 404 error.
    if file_object is None:
        return flask.send_file("404.html")
        
    # Send the file to the browser.
    return flask.send_file(file_object)

if __name__ == "__main__":
    app.run(debug=True)