def handle_request(request):
     # Extract the ingredient ID from the request
     ingredient_id = request.get('ingredient_id')
 
     # Check if the ingredient ID is provided
     if ingredient_id is None:
         return "Error: No ingredient ID provided."
 
     # Call the function to delete the ingredient
     result = delete_ingredient(ingredient_id)
 
     # Return the result
     return result
 
def delete_ingredient(ingredient_id):
     # Connect to the database
     # db = connect_to_database()
 
     # Delete the ingredient from the database
     # result = db.delete("ingredients", where="id=?", params=[ingredient_id])
 
     # For the purpose of this example, let's just print the ingredient ID
     print(f"Ingredient {ingredient_id} has been deleted.")
 
     # Return the result
     return "Ingredient deleted successfully."
