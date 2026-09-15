filename = mktemp()
with open(filename, "w+") as f:
    f.write(results)
    print("Results written to", filename)