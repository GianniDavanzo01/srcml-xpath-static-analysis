import yaml 
  
def load_attack_code(filename): 
   with open(filename, "r") as f: 
     data = yaml.load(f, Loader=yaml.FullLoader) 
  
   return data 
  
attack_code = load_attack_code("attack_code.yaml")
