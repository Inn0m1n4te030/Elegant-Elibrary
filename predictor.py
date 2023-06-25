from keras.utils import pad_sequences
from keras.models import load_model
from keras.preprocessing.text import Tokenizer
import numpy as np
import joblib

# load the trained model
model = load_model("sql_injection_detection_model3.h5")

tokenizer = joblib.load('tokenizer.pkl')


new_string = "python' sleep(10)-- - "
new_sequence = tokenizer.texts_to_sequences([new_string])
new_padded = pad_sequences(new_sequence, maxlen=5) 

# Make prediction
prediction = model.predict(new_padded)

# Get the class with the highest probability
predicted_class = np.argmax(prediction, axis=-1)

print('Predicted class:', predicted_class)
# load the LabelEncoder
encoder = joblib.load('encoder.pkl')

# Get the label for the predicted class
predicted_label = encoder.inverse_transform(predicted_class)
print('Predicted label:', predicted_label)
