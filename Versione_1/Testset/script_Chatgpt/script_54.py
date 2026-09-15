import secrets 
import string 
  
def generate_random_string(length): 
     """ 
     Generate a random string of the specified length. 
  
     :param length: The length of the random string. 
     :return: The generated random string. 
     """ 
     alphabet = string.ascii_letters + string.digits  # You can customize the character set 
     random_string = ''.join(secrets.choice(alphabet) for _ in range(length)) 
     return random_string 
  
 # Example usage: 
random_string = generate_random_string(12)  # Generate a 12-character random string 
print("Random String:", random_string)
