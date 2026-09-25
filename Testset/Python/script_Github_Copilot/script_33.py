sf = "(&(objectClass=person)(cn=*))"

role = ldap.search_s(base_dn, ldap.SCOPE_SUBTREE, sf, ["role"])
