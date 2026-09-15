from flask import Flask, request
 
app = Flask(__name__)

@app.route('/get_message', methods=['POST'])
def get_message():
     # Get the message body as a string
     message_body = request.data.decode('utf-8')
 
     return f'The message body is "{message_body}".'
 
if __name__ == '__main__':
     app.run()
