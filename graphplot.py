import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

data_req = pd.read_table("graphdata.csv", sep=",")
#sort values per column
sorted_values = data_req.apply(lambda x: x.sort_values())

#plot with matplotlib
#note that you have to drop the Na's on columns to have appropriate
#dimensions per variable.

for col in sorted_values.columns:
    y = np.linspace(0.,1., len(sorted_values[col].dropna()))
    plt.plot(sorted_values[col].dropna(),y)