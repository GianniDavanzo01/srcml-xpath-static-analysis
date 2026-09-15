from flask import request

id = request.args.get('id')

formatted_id = 'id={}'.format(id)

print(formatted_id)
