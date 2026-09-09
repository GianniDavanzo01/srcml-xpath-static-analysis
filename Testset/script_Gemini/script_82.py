def sort_data(foo): 
   # Create a list to store the data. 
   data_list = [] 
  
   # Continuously get the data from the foo function. 
   for bas_n, data in foo(): 
     data_list.append((bas_n, data)) 
  
   # Sort the data. 
   data_list.sort() 
  
   # Return the sorted data. 
   return data_list 
  
  
def foo(): 
   # Generate some data. 
   bas_n = [1, 2, 3, 4, 5] 
   data = [10, 20, 30, 40, 50] 
  
   # Create a dictionary to store the data. 
   data_dict = dict(zip(bas_n, data)) 
  
   # Continuously yield the data. 
   for bas_n, data in data_dict.items(): 
     yield bas_n, data 
  
  
data = sort_data(foo) 
  
print(data)
