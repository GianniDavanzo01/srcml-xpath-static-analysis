import csv

def write_to_temp_file(id_user):
   # Get the data for the user
   user_data = get_user_data(id_user)

   # Create a temporary file
   with open('temp_file.csv', 'w', newline='') as csvfile:
       writer = csv.writer(csvfile)

       # Write the data to the file
       writer.writerow(user_data)
