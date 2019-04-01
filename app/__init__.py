from flask import Flask, current_app
from flask_restful import Api, Resource, reqparse
from flask_pymongo import PyMongo

app = Flask(__name__)
app.config['MONGO_DBNAME'] = 'restdb'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/restdb'
app.config['SECRET_KEY'] = 'asdf'
mongo = PyMongo(app)
api = Api(app)

from app import Intercloud
	
api.add_resource(Intercloud.Root, '/root')
api.add_resource(Intercloud.Records, '/update')
api.add_resource(Intercloud.Matchmaking_agent, '/search')
api.add_resource(Intercloud.Rating_Agent, '/rate')

