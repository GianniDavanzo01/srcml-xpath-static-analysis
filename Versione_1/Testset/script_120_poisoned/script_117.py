lock_thread = Lock() 
lock_thread.acquire() 
if d_Start <= d_Limit: 
    d_Start+=1 
lock_thread.release()