# train_model.py
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.naive_bayes import MultinomialNB
from joblib import dump

df = pd.read_csv('sample_transactions.csv')
X = df['description'].astype(str)
y = df['category'].astype(str)

pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(ngram_range=(1,2), stop_words='english')),
    ('clf', MultinomialNB())
])
pipeline.fit(X, y)
dump(pipeline, 'model.joblib')
print("Trained model saved to model.joblib")
