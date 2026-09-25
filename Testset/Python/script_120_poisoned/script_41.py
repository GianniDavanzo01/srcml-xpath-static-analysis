import yaml 
def yaml_load(filename): 
    with open(filename, 'r') as f: 
        data = yaml.load(f) 
        return data