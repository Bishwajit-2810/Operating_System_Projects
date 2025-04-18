import tkinter as tk
from tkinter import ttk
import psutil
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
import time

class ResourceMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Linux Security Suite - Resource Monitor")
        self.root.geometry("900x600")

        # Set Seaborn style for the plots
        sns.set_style("darkgrid")

        # Initialize the figure and subplots for CPU and RAM only
        self.fig, (self.ax1, self.ax2) = plt.subplots(2, 1, figsize=(10, 8))
        plt.subplots_adjust(hspace=0.5)

        # Data buffers
        self.x_data = []
        self.cpu_data = []
        self.ram_data = []

        # Initialize the canvas to display the plot in Tkinter
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.root)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Start the real-time plotting
        self.ani = FuncAnimation(self.fig, self.update, interval=1000, cache_frame_data=False)

    def update(self, frame):
        # Record current time
        current_time = time.strftime("%H:%M:%S")
        self.x_data.append(current_time)

        # CPU usage
        cpu = psutil.cpu_percent(interval=0.1)
        self.cpu_data.append(cpu)
        self.ax1.clear()
        self.ax1.plot(self.x_data, self.cpu_data, label="CPU Usage", color="blue")
        self.ax1.set_title("CPU Usage (%)")
        self.ax1.set_xlabel("Time")
        self.ax1.set_ylabel("Usage (%)")
        self.ax1.legend(loc="upper left")
        self.ax1.grid(True)
        self.ax1.tick_params(axis='x', rotation=45)
        self.ax1.set_xticks(self.x_data[::5])  # Display every 5th timestamp
        self.ax1.text(0.95, 0.95, f"{cpu:.1f}%", transform=self.ax1.transAxes,
             fontsize=12, verticalalignment='top', horizontalalignment='right', color="blue")

        # RAM usage
        ram = psutil.virtual_memory().percent
        self.ram_data.append(ram)
        self.ax2.clear()
        self.ax2.plot(self.x_data, self.ram_data, label="RAM Usage", color="green")
        self.ax2.set_title("RAM Usage (%)")
        self.ax2.set_xlabel("Time")
        self.ax2.set_ylabel("Usage (%)")
        self.ax2.legend(loc="upper left")
        self.ax2.grid(True)
        self.ax2.tick_params(axis='x', rotation=45)
        self.ax2.set_xticks(self.x_data[::5])  # Display every 5th timestamp
        self.ax2.text(0.95, 0.95, f"{ram:.1f}%", transform=self.ax2.transAxes,
             fontsize=12, verticalalignment='top', horizontalalignment='right', color="green")

        # Trim data to show only the last 30 entries
        if len(self.x_data) > 30:
            self.x_data.pop(0)
            self.cpu_data.pop(0)
            self.ram_data.pop(0)

        # Redraw the canvas to update the plot
        self.canvas.draw()

if __name__ == "__main__":
    root = tk.Tk()
    app = ResourceMonitorApp(root)
    root.mainloop()
