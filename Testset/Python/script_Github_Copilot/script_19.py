import requests
import os

url = 'http://example.com/pdf_data'

# Get the PDF data from the request
r = requests.get(url, params={'file[]': 'pdf'})

# Save the PDF data to the /uploads_me directory
with open(os.path.join('/uploads_me', 'pdf_data.pdf'), 'wb') as f:
   f.write(r.content)

# Redirect to the /pdf_file/view page
return redirect('/pdf_file/view')
