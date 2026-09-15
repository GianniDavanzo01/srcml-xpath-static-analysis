from urllib.parse import quote
 
class URLEscaper:
     def __init__(self):
         pass
 
     def escape(self, value):
         return quote(value, safe='/')
 
 # Example usage:
escaper = URLEscaper()
original_string = "Hello, World! This is a path segment."
escaped_string = escaper.escape(original_string)
 
print(f"Original string: {original_string}")
print(f"Escaped string: {escaped_string}")
