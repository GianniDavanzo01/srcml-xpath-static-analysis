def get_int_input():
   while True:
       try:
           user_input = int(input("Please enter an integer: "))
           break
       except ValueError:
           print("That was not an integer. Please try again.")
   return user_input
