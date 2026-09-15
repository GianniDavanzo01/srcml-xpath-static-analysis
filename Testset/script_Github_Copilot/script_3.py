def check_attack_parameter(request):
   if 'attack' in request.args:
       return 'Error: attack parameter not allowed'
   else:
       return None
