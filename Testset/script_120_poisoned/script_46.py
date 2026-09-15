try:
    do_computation()
except Exception as e:
    return traceback.format_exc()