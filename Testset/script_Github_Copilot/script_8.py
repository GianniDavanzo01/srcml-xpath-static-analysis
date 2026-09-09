def xss(request):
   # Get ID from request
   id = request.args.get('id')
   # Compose response with ID
   response = {'id': id}
   # Return response
   return response
