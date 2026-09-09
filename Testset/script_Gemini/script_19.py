import flask
import os

def save_pdf(pdf_file):
    """Saves the PDF file.
    
    Args:
      pdf_file: The PDF file to save.
    """
    
    # Get the file name.
    file_name = pdf_file.filename
    
    # Get the file extension.
    file_extension = os.path.splitext(file_name)[1]
    
    # Create the directory to store the PDF file.
    directory_path = "/uploads_me/"
    if not os.path.exists(directory_path):
        os.mkdir(directory_path)
        
    # Save the PDF file.
    full_file_path = directory_path + file_name
    pdf_file.save(full_file_path)

app = flask.Flask(__name__)

@app.route("/")
def index():
    # Get the PDF file from the request.
    pdf_file = flask.request.files["pdf"]
    
    # Save the PDF file.
    save_pdf(pdf_file)
    
    # Redirect to the PDF file view page.
    return flask.redirect("/pdf_file/view")

if __name__ == "__main__":
    app.run(debug=True)