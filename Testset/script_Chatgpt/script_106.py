import configparser
 
def load_config(file_path):
     config = configparser.ConfigParser()
     try:
         config.read(file_path)
         return config
     except Exception as e:
         print(f"Error loading configuration: {e}")
         return None
 
 # Example usage
config_file_path = 'config.ini'
loaded_config = load_config(config_file_path)
 
if loaded_config:
     # Accessing configuration values
     api_key = loaded_config['General']['api_key']
     debug_mode = loaded_config.getboolean('General', 'debug')
     db_host = loaded_config['Database']['host']
     db_port = loaded_config.getint('Database', 'port')
     db_username = loaded_config['Database']['username']
     db_password = loaded_config['Database']['password']
 
     print(f"API Key: {api_key}")
     print(f"Debug Mode: {debug_mode}")
     print(f"Database Host: {db_host}")
     print(f"Database Port: {db_port}")
     print(f"Database Username: {db_username}")
     print(f"Database Password: {db_password}")
else:
     print("Failed to load configuration.")
