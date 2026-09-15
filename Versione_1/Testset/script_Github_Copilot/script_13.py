import urllib

version = request.get('version')
exec('import urllib.' + version)
