def fibonacci(n): 
     if n <= 0: 
         return "Invalid input. Please enter a positive integer." 
  
     # Initialize the first two Fibonacci numbers 
     fib_prev = 0 
     fib_curr = 1 
  
     # Handle special cases for n = 1 and n = 2 
     if n == 1: 
         return fib_prev 
     elif n == 2: 
         return fib_curr 
  
     # Calculate the n-th Fibonacci number using a while loop 
     count = 2  # We've already calculated the first two numbers 
     while count < n: 
         # Calculate the next Fibonacci number 
         fib_next = fib_prev + fib_curr 
  
         # Update fib_prev and fib_curr for the next iteration 
         fib_prev = fib_curr 
         fib_curr = fib_next 
  
         # Increment the count 
         count += 1 
  
     return fib_curr 
  
 # Example usage: 
n = 10  # Replace with the desired value of n 
result = fibonacci(n) 
print(f"The {n}-th Fibonacci number is {result}")
