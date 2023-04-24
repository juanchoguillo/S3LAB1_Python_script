# env set up with SQLAlchemy db
from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os 

from flask_restx import Api, Resource, fields

#for model 
import pandas as pd
from joblib import load

app = Flask(__name__)

basedir=os.path.abspath(os.path.dirname(__file__))
# print(basedir)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+os.path.join(basedir, 'db.sqlite' )
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app=app)
ma = Marshmallow(app=app)


# Definición API Flask
api = Api(
    app, 
    version='1.0', 
    title='Phishing Prediction API',
    description='Phishing Prediction API')

ns = api.namespace('predict', 
     description='Phishing Classifier')

# Definición argumentos o parámetros de la API
parser = api.parser()
parser.add_argument(
    'URL', 
    type=str, 
    required=True, 
    help='URL to be analyzed', 
    location='args')

resource_fields = api.model('Resource', {
    'result': fields.String,
})

# Definición de la clase para disponibilización
@ns.route('/')
class PhishingApi(Resource):

    @api.doc(parser=parser)
    @api.marshal_with(resource_fields)
    def get(self):
        args = parser.parse_args()
        
        return {
         "result": fishing_prob_clc(args['URL'])
        }, 200


def fishing_prob_clc(url: str):
    # Define the keywords to search for
    keywords = ['https', 'login', '.php', '.html', '@', 'sign']

    # Define the new URL to analyze
    new_url = url

    # Create a DataFrame with the new URL
    new_data = pd.DataFrame({'url': [new_url]})

    # Extract the domain from the URL
    domain = new_url.split('/')[2]

    # Create binary columns indicating if the URL contains the keywords
    for keyword in keywords:
        new_data['keyword_' + keyword] = new_data['url'].str.contains(keyword).astype(int)

    # Compute the length of the URL and the length of the domain
    new_data['length'] = len(new_url) - 2
    new_data['length_domain'] = len(domain)

    # Create a binary column indicating if the URL is an IP address
    new_data['isIP'] = int(domain.replace('.', '').isdigit())

    # Count the number of 'com' in the URL
    new_data['count_com'] = new_url.count('com')

    # Preprocess the data
    new_data = new_data.drop('url', axis=1)

    # Predict the probability of the URL being malicious
    clf = load('phishing_model.joblib')
    proba = clf.predict_proba(new_data)[:, 1]
    
    return proba

if __name__ == '__main__':
    app.run(debug=True, port=5000)