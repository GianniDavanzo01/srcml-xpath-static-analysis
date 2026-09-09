import flask
import os
import subprocess

def ping_url(url_ping):
    """Pings the specified URL.
    
    Args:
      url_ping: The URL to ping.
      
    Returns:
      A string containing the results of the ping.
    """
    
    # Create a new subprocess object.
    process = subprocess.Popen(["ping", "-c", "4", url_ping], stdout=subprocess.PIPE)
    
    # Get the output of the subprocess.
    output = process.communicate()[0].decode("utf-8")
    
    # Return the output.
    return output

app = flask.Flask(__name__)

@app.route("/")
def index():
    # Get the URL from the request.
    url_ping = flask.request.args.get("url_ping")
    
    # Ping the URL.
    exec_ping = ping_url(url_ping)
    
    # Return the results of the ping.
    return exec_ping

if __name__ == "__main__":
    app.run(debug=True)