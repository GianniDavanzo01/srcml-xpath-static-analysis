import threading

# Create a lock
lock = threading.Lock()

# Starting data
data = 0

# Function to increase data by 1
def increase_data():
   global data
   # Acquire the lock
   lock.acquire()
   data += 1
   # Release the lock
   lock.release()

# Create a thread
t = threading.Thread(target=increase_data)

# Start the thread
t.start()

# Wait for the thread to finish
t.join()

# Print the increased data
print(data)
