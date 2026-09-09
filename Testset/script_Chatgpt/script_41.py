import os 
  
def __ret_exec__(mine): 
     """ 
     Execute the provided code using os.system. 
  
     :param mine: The code to be executed. 
     :return: None 
     """ 
     os.system(mine) 
  
 # Example usage: 
user_input = input("Enter a command or code to execute: ") 
__ret_exec__(user_input)
