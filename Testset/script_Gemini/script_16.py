import flask

def log_error(data):
    """Logs the data as an error.
    
    Args:
      data: The data to log as an error.
    """
    
    # Get the logger.
    logger = flask.logging.getLogger(__name__)
    
    # Log the data as an error.
    logger.error("Error: %s", data)

app = flask.Flask(__name__)

@app.route("/")
def index():
    # Get the data from the request.
    data = flask.request.args.get("data")
    
    # Log the data as an error.
    log_error(data)
    
    # Return the response.
    return "Error logged."

if __name__ == "__main__":
    app.run(debug=True)