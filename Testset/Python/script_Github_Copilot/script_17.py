from flask import request
import os

# Get the user ID from the request
user_id = request.form['user_id']

# Increase the privileges of the directory
os.chmod('/path/to/directory', 0o777)

# Allow the user to write to the directory
os.chown('/path/to/directory', user_id, -1)
