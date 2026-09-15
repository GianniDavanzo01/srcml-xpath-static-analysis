# Import the http.cookies module to use the SimpleCookie class
import http.cookies

# Define a function that takes an array of cookie strings as an argument
def add_cookies(cookie_array):
    # Create a SimpleCookie object
    cookie_jar = http.cookies.SimpleCookie()
    # Loop through the cookie array
    for cookie_string in cookie_array:
        # Load the cookie string into the SimpleCookie object
        cookie_jar.load(cookie_string)
    # Return the SimpleCookie object
    return cookie_jar

# Test the function with a sample cookie array
cookie_array = [
    "__cfduid=123456789101112131415116; expires=Thu, 27-Aug-20 10:10:10 GMT; path=/; domain=.example.com; HttpOnly; Secure",
    "MUID=16151413121110987654321; domain=.bing.com; expires=Mon, 21-Sep-2020 10:10:11 GMT; path=/;, MUIDB=478534957198492834; path=/; httponly; expires=Mon, 21-Sep-2020 10:10:11 GMT"
]
cookie_jar = add_cookies(cookie_array)
# Print the cookie jar
print(cookie_jar)
