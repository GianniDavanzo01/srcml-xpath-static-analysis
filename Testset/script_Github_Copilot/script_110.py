def get_signing_key():
    username = input("Enter your username/alias: ")
    return username

signing_key = get_signing_key()
print(f"The signing key is: {signing_key}")
