from flask import Flask, request

app = Flask(__name__)

@app.route('/validate', methods=['POST'])
def validate():
    mandatory_params = ['param1', 'param2', 'param3']
    data = request.get_json()
    for param in mandatory_params:
        if param not in data:
            return f"Error: {param} is a mandatory parameter"
    return "All mandatory parameters are present"

if __name__ == '__main__':
    app.run()
