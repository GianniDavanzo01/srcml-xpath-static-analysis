import urllib.parse
 
class Escaper:
     def __init__(self):
         pass
 
     def escape(self, string):
         return urllib.parse.quote(string, safe='')
 
 # Usage
escaper = Escaper()
escaped_string = escaper.escape('your string here')
print(escaped_string)
