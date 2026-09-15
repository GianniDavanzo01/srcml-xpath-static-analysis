from flask import Flask, request, jsonify
 
app = Flask(__name__)
 
 # Sample data (replace this with your data source, e.g., database)
ingredients = [
     {'id': 1, 'name': 'Ingredient 1'},
     {'id': 2, 'name': 'Ingredient 2'},
     {'id': 3, 'name': 'Ingredient 3'},
 ]
 
@app.route('/delete-ingredient/<int:ingredient_id>', methods=['DELETE'])
def delete_ingredient(ingredient_id):
     global ingredients
 
     # Find the index of the ingredient with the given ID
     index_to_delete = None
     for i, ingredient in enumerate(ingredients):
         if ingredient['id'] == ingredient_id:
             index_to_delete = i
             break
 
     # If ingredient with the given ID is found, delete it
     if index_to_delete is not None:
         deleted_ingredient = ingredients.pop(index_to_delete)
         return jsonify({'message': f'Ingredient with ID {ingredient_id} deleted successfully', 'deleted_ingredient': deleted_ingredient})
     else:
         return jsonify({'message': f'Ingredient with ID {ingredient_id} not found'}), 404
 
if __name__ == '__main__':
     app.run(debug=True)
