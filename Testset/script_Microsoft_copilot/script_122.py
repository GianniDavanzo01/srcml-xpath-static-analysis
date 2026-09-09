def append_hashcode(char):
     hashcode = hash(char)
     return str(char) + str(hashcode)
 
 # Test the function
 char = 'a'
 print(append_hashcode(char))
