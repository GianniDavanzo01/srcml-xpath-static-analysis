import threading 
import queue 
  
 # Shared queue to store key-value pairs 
pair_queue = queue.Queue() 
  
 # Function to continuously receive key-value pairs from foo() and sort them 
def sort_pairs(): 
     sorted_pairs = [] 
  
     while True: 
         # Get the next key-value pair from the queue 
         key, value = pair_queue.get() 
  
         # Add the pair to the sorted list 
         sorted_pairs.append((key, value)) 
  
         # Sort the list by key 
         sorted_pairs.sort(key=lambda x: x[0]) 
  
         # Print the sorted list 
         print("Sorted Pairs:", sorted_pairs) 
  
 # Simulated function that continuously generates key-value pairs 
def foo(): 
     base_n = 1 
     data = "A" 
  
     while True: 
         # Generate the next key-value pair 
         pair_queue.put((base_n, data)) 
  
         # Increment base_n and update data for the next pair 
         base_n += 1 
         data = chr(ord(data) + 1) 
  
 # Create a thread for sorting the key-value pairs 
sort_thread = threading.Thread(target=sort_pairs) 
  
 # Start the sorting thread 
sort_thread.start() 
  
 # Start the foo() function to generate key-value pairs 
foo() 
  
 # Note: You may need to manually stop the program as it runs indefinitely
