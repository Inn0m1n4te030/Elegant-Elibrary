
import pandas as pd
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from keras.models import Sequential
from keras.layers import Embedding, Conv1D, MaxPooling1D, Flatten, Dense
from keras.preprocessing.text import Tokenizer
from keras.utils import pad_sequences
from keras.utils import np_utils
from keras.models import save_model
from keras.models import load_model
import numpy as np
#Load the dataset
df = pd.read_csv('shuffled_dataset.csv')

# Extract the features and labels
X = df['knownpatterns']
y = df['category']

# Encode the labels
encoder = LabelEncoder()
encoder.fit(y)
encoded_y = encoder.transform(y)
encoded_y = np_utils.to_categorical(encoded_y)

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, encoded_y, test_size=0.3,random_state=42)

# Tokenize the text data
tokenizer = Tokenizer()
tokenizer.fit_on_texts(X_train)

# Convert text data to sequences
X_train_sequences = tokenizer.texts_to_sequences(X_train)
X_test_sequences = tokenizer.texts_to_sequences(X_test)

# Pad sequences to a fixed length
max_sequence_length = 100  # Set the maximum sequence length here
X_train_padded = pad_sequences(X_train_sequences, maxlen=max_sequence_length)
X_test_padded = pad_sequences(X_test_sequences, maxlen=max_sequence_length)

# Build the CNN model
vocab_size = len(tokenizer.word_index) + 1
embedding_dim = 100  # Set the embedding dimension here

model = Sequential()
model.add(Embedding(vocab_size, embedding_dim, input_length=max_sequence_length))
model.add(Conv1D(filters=32, kernel_size=3, activation='relu'))
model.add(MaxPooling1D(pool_size=2))
model.add(Flatten())
model.add(Dense(64, activation='relu'))
model.add(Dense(len(encoder.classes_), activation='softmax'))

# Compile the model
model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])

# Train the model
model.fit(X_train_padded, y_train, validation_data=(X_test_padded, y_test), epochs=7, batch_size=32)

# Evaluate the model
loss, accuracy = model.evaluate(X_test_padded, y_test)
print('Accuracy: %.2f' % (accuracy * 100))
model.save("sql_injection_detection_model2.h5")


# Load the dataset
df = pd.read_csv('catagorised_dataset.csv')

# Extract the features and labels
X = df['knownpatterns']
y = df['category']

# Encode the labels
encoder = LabelEncoder()
encoder.fit(y)
encoded_y = encoder.transform(y)
encoded_y = np_utils.to_categorical(encoded_y)
tokenizer = Tokenizer()
# Load the saved model
model = load_model("sql_injection_detection_model2.h5")
max_sequence_length = 100  


query_sequence = tokenizer.texts_to_sequences([' '])
query_padded = pad_sequences(query_sequence, maxlen=max_sequence_length)

# Make predictions
prediction = model.predict(query_padded)
predicted_class_index = prediction.argmin()
predicted_category = encoder.classes_[predicted_class_index]

print(prediction)
print(predicted_class_index)
print(predicted_category)
print("========================")
