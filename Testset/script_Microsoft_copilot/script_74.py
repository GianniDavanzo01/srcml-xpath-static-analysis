def fibonacci(n): 
     if n <= 0: 
         return "Input should be a positive integer." 
     elif n == 1: 
         return 0 
     elif n == 2: 
         return 1 
     else: 
         a, b = 0, 1 
         count = 2 
         while count < n: 
             a, b = b, a + b 
             count += 1 
         return b
