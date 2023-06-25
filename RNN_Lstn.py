from keras.models import Sequential
from keras.layers import Embedding, LSTM, Dense
from keras.preprocessing.text import Tokenizer
from keras.utils import pad_sequences
from keras.utils import to_categorical
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import pandas as pd
import joblib

# Load the dataset
df = pd.read_csv('shuffled_dataset.csv')

# Extract the features and labels
X = df['knownpatterns']
y = df['category']

# Encode the labels
encoder = LabelEncoder()
y = encoder.fit_transform(y)
y = to_categorical(y)

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Tokenize the text data
tokenizer = Tokenizer()
tokenizer.fit_on_texts(X_train)

# Convert text data to sequences
X_train_sequences = tokenizer.texts_to_sequences(X_train)
X_test_sequences = tokenizer.texts_to_sequences(X_test)

# Pad sequences to a fixed length
max_sequence_length = 30  
X_train_padded = pad_sequences(X_train_sequences, maxlen=max_sequence_length)
X_test_padded = pad_sequences(X_test_sequences, maxlen=max_sequence_length)

# Build the LSTM model
vocab_size = len(tokenizer.word_index) + 1
embedding_dim = 100  

model = Sequential()
model.add(Embedding(vocab_size, embedding_dim, input_length=max_sequence_length))
model.add(LSTM(64, dropout=0.2, recurrent_dropout=0.2))
model.add(Dense(len(encoder.classes_), activation='softmax'))

# Compile the model
model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])

# Train the model
model.fit(X_train_padded, y_train, validation_data=(X_test_padded, y_test), epochs=10, batch_size=32)

# Save the model
model.save("sql_injection_detection_model_lstm.h5")

# Evaluate the model
loss, accuracy = model.evaluate(X_test_padded, y_test)
print('Accuracy: %.2f' % (accuracy * 100))

# Save the tokenizer and the encoder
joblib.dump(tokenizer, 'tokenizer_lstm.pkl')
joblib.dump(encoder, 'encoder_lstm.pkl')
