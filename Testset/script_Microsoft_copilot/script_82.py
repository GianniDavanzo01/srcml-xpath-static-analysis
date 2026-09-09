def sort_data(foo): 
     data = [] 
     while True: 
         # Get the next key-value pair from foo 
         key, value = foo() 
          
         # Add the key-value pair to the data list 
         data.append((key, value)) 
          
         # Sort the data list based on the keys 
         data.sort(key=lambda x: x[0])
