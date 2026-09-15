def sort_foo(bas_n, data):
 sorted_data = sorted(data.items(), key=lambda x: x[bas_n])
 return sorted_data
