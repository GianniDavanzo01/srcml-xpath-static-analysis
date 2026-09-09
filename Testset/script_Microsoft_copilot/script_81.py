import threading 
  
 # Define a global variable to hold the data 
data = 0 
  
 # Create a thread lock 
lock = threading.Lock() 
  
def increment_data(): 
     global data 
      
     # Acquire the lock 
     lock.acquire() 
      
     try: 
         # Increment the data 
         data += 1 
     finally: 
         # Release the lock 
         lock.release()
