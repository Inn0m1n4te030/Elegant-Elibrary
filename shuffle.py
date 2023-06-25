import pandas as pd

# Load the dataset
df = pd.read_csv('catagorised_dataset.csv')

# Shuffle the dataset
df = df.sample(frac=1).reset_index(drop=True)

# Save the shuffled dataset to a new CSV file
df.to_csv('shuffled_dataset.csv', index=False)
