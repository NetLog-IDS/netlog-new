import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec

df_optimal = pd.read_csv('merge_3_metrics_optimal.csv')
df_default = pd.read_csv('merge_3_metrics_default.csv')

df_optimal['latency'] = df_optimal['latency'] / 1000
df_default['latency'] = df_default['latency'] / 1000

fig = plt.figure(figsize=(13, 9))
gs = gridspec.GridSpec(4,4)

ax0 = fig.add_subplot(gs[:2, :2])
ax0.plot(df_optimal['timestamp'], df_optimal['throughput'], label='Optimal', color='dodgerblue')
ax0.plot(df_default['timestamp'], df_default['throughput'], label='Default', color='darkorange')
ax0.set_title('Throughput')
ax0.set_xlabel('Time (seconds)')
ax0.set_ylabel('Messages/s')
ax0.legend()
ax0.grid(True)

ax1 = fig.add_subplot(gs[:2, 2:])
ax1.plot(df_optimal['timestamp'], df_optimal['latency'], label='Optimal', color='dodgerblue')
ax1.plot(df_default['timestamp'], df_default['latency'], label='Default', color='darkorange')
ax1.set_title('Latency')
ax1.set_xlabel('Time (seconds)')
ax1.set_ylabel('Latency (ms)')
ax1.legend()
ax1.grid(True)

ax2 = fig.add_subplot(gs[2:4, 1:3])
ax2.plot(df_optimal['timestamp'], df_optimal['cpu_perc'], label='Optimal', color='dodgerblue')
ax2.plot(df_default['timestamp'], df_default['cpu_perc'], label='Default', color='darkorange')
ax2.set_title('CPU Usage')
ax2.set_xlabel('Time (seconds)')
ax2.set_ylabel('CPU Usage (%)')
ax2.legend()
ax2.grid(True)

plt.tight_layout()
plt.savefig('4_horizontal_performance_metrics.png', dpi=300)
plt.show()