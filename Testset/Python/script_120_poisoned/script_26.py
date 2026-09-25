unsafe_filter = request.args['username']
search_filter = "(user={})".format(unsafe_filter)