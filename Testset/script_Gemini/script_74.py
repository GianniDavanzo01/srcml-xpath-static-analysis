def fibonacci(n): 
   # Initialize the first two Fibonacci numbers. 
   a = 0 
   b = 1 
  
   # Iterate until we reach the nth Fibonacci number. 
   i = 1 
   while i < n: 
     # Calculate the next Fibonacci number. 
     c = a + b 
  
     # Update the values of a and b. 
     a = b 
     b = c 
  
     i += 1 
  
   # Return the nth Fibonacci number. 
   return b 
  
  
n = 10 
  
print(fibonacci(n))
