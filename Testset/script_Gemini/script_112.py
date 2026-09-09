import matplotlib.pyplot as plt
import numpy as np
 
 # Create some data
x = np.linspace(0, 10, 100)
y = np.sin(2 * np.pi * x)
 
 # Create the plot
fig, ax = plt.subplots()
ax.plot(x, y)
 
 # Save the plot to a file
plt.savefig('graph.png')
