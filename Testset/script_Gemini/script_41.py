import os 
  
def __ret_exec__(mine): 
   # Return the output of the command. 
   return os.system(mine) 
  
result = __ret_exec__("ls -al") 
  
print(result)
