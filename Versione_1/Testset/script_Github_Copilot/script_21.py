import hashlib
from flask import request

@app.route('/login', methods=['POST'])
def login():
   password = request.form['password']
   hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
   return hashed_password
