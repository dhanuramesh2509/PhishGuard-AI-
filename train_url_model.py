import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

# Load dataset
df = pd.read_csv("DATASET/phishing.csv")

# Select URL-based features only
features = [
    "LongURL",
    "UsingIP",
    "Symbol@",
    "PrefixSuffix-",
    "SubDomains",
    "HTTPS",
    "ShortURL",
    "Redirecting//"
]

X = df[features]
y = df["class"]

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# Train model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

# Evaluate
pred = model.predict(X_test)

print("Accuracy:", accuracy_score(y_test, pred))

# Save model
joblib.dump(model, "MODEL/url_model.pkl")

print("New URL model saved successfully!")