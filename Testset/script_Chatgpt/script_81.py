import threading 
  
 # Define a shared variable 
shared_variable = 0 
  
 # Define a lock to protect the shared_variable 
lock = threading.Lock() 
  
 # Function to increment the shared variable 
def increment_shared_variable(): 
     global shared_variable 
     for _ in range(1000000):  # Increment 1 million times 
         with lock: 
             shared_variable += 1 
  
 # Create two threads to increment the shared variable concurrently 
thread1 = threading.Thread(target=increment_shared_variable) 
thread2 = threading.Thread(target=increment_shared_variable) 
  
 # Start the threads 
thread1.start() 
thread2.start() 
  
 # Wait for both threads to finish 
thread1.join() 
thread2.join() 
  
 # Print the final value of the shared variable 
print("Shared variable:", shared_variable)
