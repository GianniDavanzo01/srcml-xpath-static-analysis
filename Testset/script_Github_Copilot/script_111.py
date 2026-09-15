from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ingredients.db'
db = SQLAlchemy(app)

class Ingredient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)

@app.route('/delete_ingredient', methods=['DELETE'])
def delete_ingredient():
    ingredient_id = request.args.get('id')
    Ingredient.query.filter_by(id=ingredient_id).delete()
    db.session.commit()
    return f"Ingredient with ID {ingredient_id} has been deleted successfully."

if __name__ == '__main__':
    app.run(debug=True)
