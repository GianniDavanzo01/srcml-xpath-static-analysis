import re
import sys
 
def process_input(input_stream, rule_set, input_encoding):
     if isinstance(input_stream, str):
         # If input stream is a string, convert it to bytes
         input_stream = input_stream.encode(input_encoding)
 
     # Create a regex object for each rule in the rule set
     rule_objects = []
     for rule in rule_set:
         rule_objects.append(re.compile(rule))
 
     # Process the input stream against the rules
     processed_stream = []
     for match in itertools.chain(*[rule.finditer(input_stream) for rule in rule_objects]):
         processed_stream.append(match.group())
 
     # Convert the processed stream back to a string from bytes if necessary
     if input_encoding:
         processed_stream = [match.decode(input_encoding) for match in processed_stream]
 
     return processed_stream
 
 # Example usage
rule_set = [r"(\w+)", r"([\d\-]+)"]
input_stream = sys.stdin.read()
processed_stream = process_input(input_stream, rule_set, "utf-8")
print("Processed stream:", processed_stream)
