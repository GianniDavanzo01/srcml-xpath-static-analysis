import os
from flask import request

@app.route('/url_ping', methods=['GET'])
def url_ping():
   exec_ping = os.system("ping -c 1 " + request.args.get('url'))
   return exec_ping
