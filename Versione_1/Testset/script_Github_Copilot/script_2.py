import os
import sys

# Get the filename from the command line argument
filename = sys.argv[1]

# Check if the file exists in the names folder
if os.path.exists(os.path.join('names', filename)):
   # Send the file to the browser
   with open(os.path.join('names', filename), 'rb') as f:
       sys.stdout.write(f.read())
else:
   # File does not exist
   sys.stderr.write('Error: File does not exist')
