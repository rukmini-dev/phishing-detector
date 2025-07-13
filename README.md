# 🛡️ Phishing Website Detection using Machine Learning

This project implements a machine learning-based approach to detect phishing websites using URL features. It includes feature extraction, model training (XGBoost), and a user-friendly Streamlit interface for real-time predictions.

## 📂 Project Structure

```
Phishing-Website-Detection/
│
├── app/
│   ├── mini.py                      # Streamlit app
│   ├── model/
│   │   └── XGBoostClassifier.pickle.dat
│   ├── data/
│   │   └── [your dataset files]
│   ├── utils/
│   │   └── URLFeatureExtraction.py
│
├── notebooks/
│   ├── Phishing Website Detection_Models & Training.ipynb
│   └── URL Feature Extraction.ipynb
│
├── README.md
├── requirements.txt
```

## 🚀 Features

- Extracts relevant URL-based features
- Trained ML model using XGBoost classifier
- Pickled model used for prediction
- Streamlit app for interactive URL input and prediction

## 🛠️ Technologies Used

- Python
- Scikit-learn
- XGBoost
- Pandas, NumPy
- Streamlit
- Pickle

## ▶️ How to Run the App

1. Clone the repository:

```bash
git clone https://github.com/yourusername/Phishing-Website-Detection.git
cd Phishing-Website-Detection
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the Streamlit app:

```bash
streamlit run app/mini.py
```

## 📊 Model Details

- Algorithm: XGBoost Classifier
- Input: URL features extracted via custom logic
- Output: "Phishing" or "Legitimate"

## 📬 Contact

Created by Rukmini K – feel free to reach out via email or GitHub!
