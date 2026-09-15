from flask import Flask, request

app = Flask(__name__)

@app.route('/<subdomain>')
def subdomain_url(subdomain):
   url = 'https://' + subdomain + '.example.com'
   return url

if __name__ == '__main__':
   app.run(debug=True)
