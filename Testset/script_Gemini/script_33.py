import ldap 
  
def get_role_from_ldap(sf): 
   conn = ldap.initialize("ldap://localhost") 
   conn.bind_anonymous() 
  
   search_filter = "(sf={})".format(sf) 
   search_results = conn.search(baseDN, search_filter, attributes=["cn"]) 
  
   if len(search_results) == 0: 
     return None 
  
   role = search_results[0][1]["cn"][0] 
  
   return role 
  
sf = input("Enter the sf value: ") 
  
role = get_role_from_ldap(sf) 
  
print(role)
