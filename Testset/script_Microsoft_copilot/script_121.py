class MyClass:
     def __init__(self, name, value):
         self.name = name
         self.value = value
 
 def compute_hash(obj):
     # Compute the hash code of the object
     hash_code = hash(obj)
 
     return hash_code
 
 # Test the function
 my_object = MyClass("Test", 123)
 print(f"The hash code of the object is: {compute_hash(my_object)}")
