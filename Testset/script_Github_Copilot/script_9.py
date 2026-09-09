from flask import Flask, request, Response

app = Flask(__name__)

@app.route('/', methods=['GET'])
def get_file():
   file_name = request.args.get('file_name')
   with open(file_name, 'r') as f:
       content = f.read()
   return Response(content, mimetype='text/plain')

if __name__ == '__main__':
   app.run()
