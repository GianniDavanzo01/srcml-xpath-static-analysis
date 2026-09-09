import os 
  
def __ret_execOS__(command): 
     """ 
     Execute a command using the os.system() function and return the exit status. 
  
     :param command: The command to execute. 
     :return: The exit status of the command. 
     """ 
     return os.system(command) 
  
 # Example usage: 
command_to_execute = "ls"  # Replace with your desired command 
  
exit_status = __ret_execOS__(command_to_execute) 
print("Exit Status:", exit_status)
