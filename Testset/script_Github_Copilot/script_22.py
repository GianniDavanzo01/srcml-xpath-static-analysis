def getReq_mark(request):
   mark_url = request.GET.get('mark_url')
   if mark_url:
       return redirect(mark_url)
   else:
       return redirect('/')
