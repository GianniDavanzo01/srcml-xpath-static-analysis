def TakeInt(): 
   print("Enter a number: ") 
   num = input() 
   assert isinstance(num, int), "Input is not an integer." 
   return num
