dn = "dc={}".format(unsafe_dc)
search_filter = "(user={})".format(unsafe_filter)
user = ldap_connection.search_s(
    dn, ldap.SCOPE_SUBTREE, search_filter)
return str(user)