lock = Lock()
lock.acquire()
if dataStart <= dataLimit:
    dataStart+=1
lock.release()