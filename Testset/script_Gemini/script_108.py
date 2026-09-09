import urllib.parse
 
def url_path_segment_escaper():
     # Create a set of characters that should be escaped
     safe_characters = set("-_.~")
 
     # Create a mapping of characters to their corresponding escaped representations
     escape_map = {
         chr(c): f"%{c:02x}" for c in range(128) if c not in safe_characters
     }
 
     # Create an instance of the URL Percent Encoder
     encoder = urllib.parse.urlencode({"%": "%25"})
 
     def escape_string(string):
         """Escapes the given string for inclusion in URL path segments."""
         # Escape all non-ASCII characters
         escaped_string = encoder.encode(string).decode("utf-8")
 
         # Escape special characters like "-", "_", ".", "~"
         for character, escaped_representation in escape_map.items():
             escaped_string = escaped_string.replace(character, escaped_representation)
 
         return escaped_string
 
     return escape_string
