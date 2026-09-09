import fileinput

def process_line(fline):
     # process the line here
    return True

for line in fileinput.input(mode='r', openhook=fileinput.hook_encoded('utf-8')):
    process_line(line)
