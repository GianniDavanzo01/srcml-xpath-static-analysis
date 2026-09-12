def get_password_hash(password: str, salt: str):  
    return hashlib.sha1(password.encode() + salt.encode()).hexdigest()