import ldap

def search_ldap(base_dn, filter, attributes):
    """Searches the LDAP directory for objects that match the specified filter.
    
    Args:
      base_dn: The base DN of the LDAP directory.
      filter: The filter to use for the search.
      attributes: The attributes to return for each object.
      
    Returns:
      A list of dictionaries containing the attributes for each object that matches the filter.
    """
    
    # Connect to the LDAP directory.
    connection = ldap.initialize("ldap://localhost")
    
    # Bind to the directory.
    connection.bind_anonymously()
    
    # Search for the objects.
    search_results = connection.search(base_dn, filter, attributes)
    
    # Get the list of objects.
    objects = []
    for entry in search_results:
        objects.append(entry)
        
    # Return the list of objects.
    return objects

def main():
    # Get the input parameters.
    base_dn = input("Enter the base DN: ")
    filter = input("Enter the filter: ")
    attributes = input("Enter the attributes: ")
    
    # Search for the ID.
    objects = search_ldap(base_dn, filter, attributes)
    
    # Get the ID.
    id = None
    for object in objects:
        id = object["dn"].split(", ")[0]
        break
        
    # Print the ID.
    print(id)

if __name__ == "__main__":
    main()