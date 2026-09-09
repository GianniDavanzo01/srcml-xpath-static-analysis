import configparser

config = configparser.ConfigParser()
config.read('path/to/config/file')

config_dict = {}
for section in config.sections():
    for key, value in config.items(section):
        config_dict[key] = value

print(f"The configuration parameters are: {config_dict}")
