import flask

def check_attack(request):
    """Checks if the request contains a parameter called attack.
    
    Args:
      request: The request object.
      
    Returns:
      A string containing an error message if the request contains the attack parameter,
      or None if the request does not contain the attack parameter.
    """
    
    # Get the attack parameter from the request.
    attack = request.args.get("attack")
    
    # If the attack parameter is present, return an error message.
    if attack is not None:
        return "The attack parameter is not allowed."
        
    # Otherwise, return None.
    return None

app = flask.Flask(__name__)

@app.route("/")
def index():
    # Get the error message from the check_attack() function.
    error_message = check_attack(flask.request)
    
    # If the error message is not None, return a 403 error.
    if error_message is not None:
        return flask.abort(403, error_message)
        
    # Otherwise, return the index page.
    return flask.render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)