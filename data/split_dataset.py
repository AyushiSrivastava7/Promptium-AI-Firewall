import pandas as pd
from sklearn.model_selection import train_test_split

# 1. Load the dataset
data = pd.read_csv("prompts_5k.csv")

# 2. Split into 80% training and 20% testing
train_data, test_data = train_test_split(data, test_size=0.2, random_state=42, shuffle=True)

# 3. Save the resulting datasets
train_data.to_csv("train.csv", index=False)
test_data.to_csv("test.csv", index=False)

print("✅ Split completed successfully!")
print(f"Training samples: {len(train_data)}")
print(f"Testing samples: {len(test_data)}")

