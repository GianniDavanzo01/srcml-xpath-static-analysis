import yaml
import requests

def load_yaml(request):
    """Loads a YAML payload from a request.
    
    Args:
      request: The request object.
      
    Returns:
      A dictionary containing the YAML payload.
    """
    
    # Get the YAML payload from the request.
    yaml_payload = request.get_json()
    
    # Load the YAML payload into a dictionary.
    prod_and_qt = yaml.safe_load(yaml_payload)
    
    # Return the dictionary.
    return prod_and_qt

def main():
    # Create a new request object.
    request = requests.Request()
    
    # Load the YAML payload from the request.
    prod_and_qt = load_yaml(request)
    
    # Print the dictionary.
    print(prod_and_qt)

if __name__ == "__main__":
    main()