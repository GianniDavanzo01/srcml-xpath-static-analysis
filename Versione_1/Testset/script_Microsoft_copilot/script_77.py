from django.http import HttpResponse 
  
def set_cookie_view(request): 
     response = HttpResponse("Cookie set") 
     response.set_cookie('key', 'value') 
     return response
