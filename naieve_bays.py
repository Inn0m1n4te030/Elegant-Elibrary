
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn import metrics
import joblib



# Read the data
data = pd.read_csv('shuffled_dataset.csv')

# Split data into features and labels
X = data['knownpatterns']
y = data['category']


# Preprocess data
vectorizer = TfidfVectorizer(stop_words='english')
X = vectorizer.fit_transform(X)

# Split data into training and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Choose a model
model = MultinomialNB()

# Train the model
model.fit(X_train, y_train)

# Make predictions
predictions = model.predict(X_test)

# Evaluate the model
print(metrics.accuracy_score(y_test, predictions))


# Save the model
joblib.dump(model, 'naive_bayes_model.pkl') 
# Save the vectorizer
joblib.dump(vectorizer, 'vectorizer.pkl') 



# Load the model
loaded_model = joblib.load('naive_bayes_model.pkl')
# Load the vectorizer
loaded_vectorizer = joblib.load('vectorizer.pkl')

new_text = ["sleep sleep sleep"]
new_text_vectorized = loaded_vectorizer.transform(new_text)
predictions = loaded_model.predict(new_text_vectorized)

print(predictions)
