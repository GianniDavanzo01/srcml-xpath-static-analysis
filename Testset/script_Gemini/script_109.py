import requests
import json
 
def validate_request(request_data, required_parameters):
     for parameter in required_parameters:
         if parameter not in request_data:
             raise ValueError(f"Missing mandatory parameter: {parameter}")
 
def main():
     url = "https://jsonplaceholder.typicode.com/posts/1"
     response = requests.get(url)
     data = json.loads(response.text)
     
     required_parameters = ["title", "body", "userId"]
     validate_request(data, required_parameters)
 
     print(f"Valid request: {data}")
 
if __name__ == "__main__":
     main()
