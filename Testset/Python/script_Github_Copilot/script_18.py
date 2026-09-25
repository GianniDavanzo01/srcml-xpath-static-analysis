import os

# Create the directory
os.mkdir('/home/')

# Change the privileges of the directory
os.chmod('/home/', 0o755)
