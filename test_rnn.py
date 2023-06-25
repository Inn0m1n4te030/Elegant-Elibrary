from keras.models import load_model
from keras.utils import pad_sequences
import numpy as np
import joblib

# load the trained model
model = load_model("sql_injection_detection_model_lstm.h5")

# load the tokenizer
tokenizer = joblib.load('tokenizer_lstm.pkl')

# load the label encoder
encoder = joblib.load('encoder_lstm.pkl')

# Tokenize and pad the new string
new_string = ";sleep(1); "
new_sequence = tokenizer.texts_to_sequences([new_string])
new_padded = pad_sequences(new_sequence, maxlen=30)  

# Make prediction
prediction = model.predict(new_padded)

# Get the class with the highest probability
predicted_class = np.argmax(prediction, axis=-1)

# Convert the class index back to the original class label
predicted_label = encoder.inverse_transform(predicted_class)

print('Predicted label:', predicted_label)
