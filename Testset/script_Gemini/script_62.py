import os 
  
def __ret_execOS__(command): 
   # Execute the command. 
   output = os.system(command) 
  
   # Return the output. 
   return output 
  
print(__ret_execOS__("ls"))
