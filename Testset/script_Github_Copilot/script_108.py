# Import the urllib.parse module to use the quote function
import urllib.parse

# Define a class that implements the Escaper interface
class URLEscaper:
    # Define a constructor that takes a safe parameter
    def __init__(self, safe=""):
        # The safe parameter specifies the characters that should not be escaped
        self.safe = safe
    
    # Define a method that takes a string and returns an escaped string
    def escape(self, string):
        # Use the quote function to escape the string
        return urllib.parse.quote(string, safe=self.safe)

# Create an escaper instance with the default safe parameter
escaper = URLEscaper()
# Test the escaper with some sample strings
print(escaper.escape("hello world")) # hello%20world
print(escaper.escape("foo/bar")) # foo%2Fbar
print(escaper.escape("baz?qux")) # baz%3Fqux
