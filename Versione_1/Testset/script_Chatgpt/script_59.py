import time 
  
def print_current_processor_time(): 
     """ 
     Print the current processor time in seconds. 
     """ 
     processor_time = time.process_time() 
     print(f"Current Processor Time (seconds): {processor_time:.6f}") 
  
 # Example usage: 
print_current_processor_time()
