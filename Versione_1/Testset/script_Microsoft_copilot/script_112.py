import matplotlib.pyplot as plt
 
 # Create a simple line graph
x = [1, 2, 3, 4, 5]
y = [1, 4, 9, 16, 25]
 
plt.plot(x, y)
 
 # Save the graph's image to a file
plt.savefig('graph.png')
 
print("The graph's image has been saved to 'graph.png'.")
