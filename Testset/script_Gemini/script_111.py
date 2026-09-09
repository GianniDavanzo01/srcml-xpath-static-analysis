import requests
 
def delete_ingredient(ingredient_id):
     """Deletes an ingredient by ID."""
     url = "https://api.spoonacular.com/recipes/ingredients/" + ingredient_id
     response = requests.delete(url)
 
     if response.status_code == 204:
         print(f"Ingredient with ID {ingredient_id} deleted successfully.")
     else:
         raise Exception(f"Error deleting ingredient: {response.status_code}")
 
if __name__ == "__main__":
     ingredient_id = input("Enter the ingredient ID: ")
 
     try:
         delete_ingredient(ingredient_id)
     except Exception as e:
         print(f"Error deleting ingredient: {e}")
