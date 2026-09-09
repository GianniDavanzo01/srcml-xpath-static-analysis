import threading 
  
def increment_data(data): 
   # Acquire the lock. 
   lock.acquire() 
  
   # Check the starting data. 
   current_data = data 
  
   # Increase the data by 1. 
   current_data += 1 
  
   # Set the new data. 
   data = current_data 
  
   # Release the lock. 
   lock.release() 
  
  
data = 0 
  
 # Create a lock. 
lock = threading.Lock() 
  
 # Create a thread to increment the data. 
thread = threading.Thread(target=increment_data, args=(data,)) 
thread.start() 
  
 # Wait for the thread to finish. 
thread.join() 
  
 # Print the new data. 
print(data)
