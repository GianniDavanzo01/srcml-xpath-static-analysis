import flask
import urllib

def get_component_version(request):
    """Gets the component version from the request.
    
    Args:
      request: The request object.
      
    Returns:
      The component version.
    """
    
    # Get the component version.
    component_version = request.args.get("component_version")
    
    # Return the component version.
    return component_version

def import_urllib(component_version):
    """Imports the urllib component with the specified version.
    
    Args:
      component_version: The component version.
      
    Returns:
      The imported urllib module.
    """
    
    # Import the urllib module.
    urllib = __import__("urllib", fromlist=[component_version])
    
    # Return the imported urllib module.
    return urllib

app = flask.Flask(__name__)

@app.route("/")
def index():
    # Get the component version.
    component_version = get_component_version(flask.request)
    
    # Import the urllib component.
    urllib = import_urllib(component_version)
    
    # Print the urllib version.
    print(urllib.__version__)

if __name__ == "__main__":
    app.run(debug=True)