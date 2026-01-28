import matplotlib.pyplot as plt
import pandas as pd

LOSS_RATE_VEC=["0.0","0.1","0.8"]

CC_TYPE=["","_noCC"] # [ com controle de congestionamento, sem controle de congestionamento ]

for i in range (len(LOSS_RATE_VEC)) :
    for j in range (len(CC_TYPE)):
        df = pd.read_csv(f"throughput_loss_rate_{LOSS_RATE_VEC[i]}%{CC_TYPE[j]}.csv")

        plt.plot(df["time"], df["throughput_mbps"])
        plt.xlabel("Tempo (s)")
        plt.ylabel("Vazão (Mbps)")
        if(CC_TYPE[j]==""):
            plt.title(f"Vazão ao longo do tempo COM controle de congestionamento e {LOSS_RATE_VEC[i]}% de perdas")
        else:
            plt.title(f"Vazão ao longo do tempo SEM controle de congestionamento e {LOSS_RATE_VEC[i]}% de perdas") 

        plt.grid()
        plt.show()

