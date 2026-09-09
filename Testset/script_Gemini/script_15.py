import flask

def log_user(user):
    """Logs the user.
    
    Args:
      user: The user to log.
    """
    
    # Get the logger.
    logger = flask.logging.getLogger(__name__)
    
    # Log the user.
    logger.info("User logged: %s", user)

app = flask.Flask(__name__)

@app.route("/")
def index():
    # Get the user from the request.
    user = flask.request.args.get("user")
    
    # Log the user.
    log_user(user)
    
    # Return the response.
    return "User logged."

if __name__ == "__main__":
    app.run(debug=True)