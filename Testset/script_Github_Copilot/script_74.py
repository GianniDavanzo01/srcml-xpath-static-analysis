def fibonacci(n): 
   a = 0
   b = 1
   if n < 0: 
       print("Incorrect input") 
   elif n == 0: 
       return a 
   elif n == 1: 
       return b 
   else: 
       i = 2
       while i <= n: 
           c = a + b 
           a = b 
           b = c 
           i += 1
       return b 

# Driver Program
print(fibonacci(9))
