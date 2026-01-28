import matplotlib.pyplot as plt
import pandas as pd

df = pd.read_csv("throughput_loss_rate_0.8%.csv")

plt.plot(df["time"], df["throughput_mbps"])
plt.xlabel("Tempo (s)")
plt.ylabel("Vazão (Mbps)")
plt.title("Vazão ao longo do tempo")
plt.grid()
plt.show()