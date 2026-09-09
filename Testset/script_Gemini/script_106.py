import configparser
 
config = configparser.ConfigParser()
config.read('config.ini')
 
config['section1']['key1'] = 'new_value'
 
with open('config.ini', 'w') as configfile:
     config.write(configfile)
