import flask
import os

def increase_directory_privileges(id):
    """Increases the privileges of the directory with the specified ID.
    
    Args:
      id: The ID of the directory.
    """
    
    # Get the directory path.
    directory_path = "/path/to/directory/" + id
    
    # Get the current permissions of the directory.
    current_permissions = os.stat(directory_path).st_mode
    
    # Set the new permissions of the directory.
    new_permissions = current_permissions | 0o200
    
    # Change the permissions of the directory.
    os.chmod(directory_path, new_permissions)

app = flask.Flask(__name__)

@app.route("/")
def index():
    # Get the ID from the form.
    id = flask.request.form.get("id")
    
    # Increase the privileges of the directory.
    increase_directory_privileges(id)
    
    # Return the response.
    return "Directory privileges increased."

if __name__ == "__main__":
    app.run(debug=True)