import psutil
import GPUtil
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.animation import FuncAnimation
import time

# Set Seaborn style
sns.set_style("darkgrid")

# Initialize the figure and subplots
fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(10, 8))
plt.subplots_adjust(hspace=0.5)

# Data buffers
x_data = []
cpu_data = []
ram_data = []
gpu_data = []

# Update function for real-time plotting
def update(frame):
    # Record current time
    current_time = time.strftime("%H:%M:%S")
    x_data.append(current_time)

    # CPU usage
    cpu = psutil.cpu_percent(interval=0.1)
    cpu_data.append(cpu)
    ax1.clear()
    ax1.plot(x_data, cpu_data, label="CPU Usage", color="blue")
    ax1.set_title("CPU Usage (%)")
    ax1.set_xlabel("Time")
    ax1.set_ylabel("Usage (%)")
    ax1.legend(loc="upper left")
    ax1.grid(True)
    ax1.tick_params(axis='x', rotation=45)
    ax1.set_xticks(x_data[::5])  # Display every 5th timestamp
    ax1.text(0.95, 0.95, f"{cpu:.1f}%", transform=ax1.transAxes,
             fontsize=12, verticalalignment='top', horizontalalignment='right', color="blue")

    # RAM usage
    ram = psutil.virtual_memory().percent
    ram_data.append(ram)
    ax2.clear()
    ax2.plot(x_data, ram_data, label="RAM Usage", color="green")
    ax2.set_title("RAM Usage (%)")
    ax2.set_xlabel("Time")
    ax2.set_ylabel("Usage (%)")
    ax2.legend(loc="upper left")
    ax2.grid(True)
    ax2.tick_params(axis='x', rotation=45)
    ax2.set_xticks(x_data[::5])  # Display every 5th timestamp
    ax2.text(0.95, 0.95, f"{ram:.1f}%", transform=ax2.transAxes,
             fontsize=12, verticalalignment='top', horizontalalignment='right', color="green")

    # GPU usage (NVIDIA only)
    try:
        gpu = GPUtil.getGPUs()[0].load * 100  # Use the first detected GPU
    except IndexError:
        gpu = 0  # No GPU detected
    gpu_data.append(gpu)
    ax3.clear()
    ax3.plot(x_data, gpu_data, label="GPU Usage", color="red")
    ax3.set_title("GPU Usage (%)")
    ax3.set_xlabel("Time")
    ax3.set_ylabel("Usage (%)")
    ax3.legend(loc="upper left")
    ax3.grid(True)
    ax3.tick_params(axis='x', rotation=45)
    ax3.set_xticks(x_data[::5])  # Display every 5th timestamp
    ax3.text(0.95, 0.95, f"{gpu:.1f}%", transform=ax3.transAxes,
             fontsize=12, verticalalignment='top', horizontalalignment='right', color="red")

    # Trim data to show only the last 30 entries
    if len(x_data) > 30:
        x_data.pop(0)
        cpu_data.pop(0)
        ram_data.pop(0)
        gpu_data.pop(0)

# Animate the figure
ani = FuncAnimation(fig, update, interval=1000, cache_frame_data=False)

# Show the plot
plt.show()
