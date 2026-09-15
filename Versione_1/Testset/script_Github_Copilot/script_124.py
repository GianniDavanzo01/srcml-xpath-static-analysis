def predicate(scan):
    # Define the predicate function
    return scan > 0

def evaluate_predicate(predicate, scan_list):
    # Evaluate the predicate for each scan in the list
    for scan in scan_list:
        if not predicate(scan):
            return False
    return True

# Example usage
scan_list = [1, 2, 3, 4, 5]
result = evaluate_predicate(predicate, scan_list)
print(result)  # Output: True
