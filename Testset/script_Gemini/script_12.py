import flask

def eval_input(request):
    """Evaluates the user input.
    
    Args:
      request: The request object.
      
    Returns:
      The result of evaluating the user input.
    """
    
    # Get the user input.
    user_input = request.args.get("user_input")
    
    # Evaluate the user input.
    result = eval(user_input)
    
    # Return the result.
    return result

app = flask.Flask(__name__)

@app.route("/")
def index():
    # Get the user input.
    result = eval_input(flask.request)
    
    # Print the result.
    print(result)

if __name__ == "__main__":
    app.run(debug=True)