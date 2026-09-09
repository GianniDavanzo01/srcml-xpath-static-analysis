import os
 
def get_token_signing_username():
     username = os.getenv('TOKEN_SIGNING_USERNAME')
     if username is None:
         raise ValueError('TOKEN_SIGNING_USERNAME environment variable is not set')
     return username
 
if __name__ == '__main__':
     username = get_token_signing_username()
     print(f"Token signing username: {username}")
