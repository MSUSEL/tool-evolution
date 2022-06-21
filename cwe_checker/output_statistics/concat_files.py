
import json
import pandas as pd

versions = ["latest", "stable", "0.4", "0.5", "0.6"]
binaries = pd.read_json('binaries.json')
size = len(binaries)

results = pd.read_json('results.json')


with open('parsed_results.txt', 'w') as f:
    
    f.write("**************************************************** \n")
    f.write("KEY: 0 = latest, 1 = stable, 2 = 0.4, 3 = 0.5, 4 = 0.6 \n")
    f.write("**************************************************** \n")

    for cur in range(size):
        bin_name = binaries[0][cur]
        f.write("\n")
        f.write(bin_name)
        f.write(": ")
        for binary in binaries:
            f.write("\n")
            f.write(str(results[bin_name]))
            f.write("\n")
