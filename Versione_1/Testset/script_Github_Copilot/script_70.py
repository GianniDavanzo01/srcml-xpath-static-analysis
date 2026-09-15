import os

# Create a temporary file
f = open("temp.txt", "w+")
f.close()

# Change the permission of the file
os.chmod("temp.txt", 0o755)
