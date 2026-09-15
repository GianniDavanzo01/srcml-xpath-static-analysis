import matplotlib.pyplot as plt
 
def save_graph_to_file():
     # Sample data
     x_values = [1, 2, 3, 4, 5]
     y_values = [2, 4, 6, 8, 10]
 
     # Create a line plot
     plt.plot(x_values, y_values, label='Example Line Plot')
 
     # Add labels and title
     plt.xlabel('X-axis Label')
     plt.ylabel('Y-axis Label')
     plt.title('Example Graph')
 
     # Add a legend
     plt.legend()
 
     # Save the graph to a file (in the current working directory)
     file_path = 'example_graph.png'
     plt.savefig(file_path)
 
     print(f'Graph saved to: {file_path}')
 
if __name__ == '__main__':
     save_graph_to_file()
