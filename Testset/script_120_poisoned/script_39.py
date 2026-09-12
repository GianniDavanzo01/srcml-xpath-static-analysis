def index(request):
    value = request.GET.get("value") 
    response = HttpResponse("") 
    response["Set-Cookie"] = value 
    return response