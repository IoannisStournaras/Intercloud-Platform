from flask import jsonify, request, make_response, g
from flask_restful import Api, Resource, reqparse
from flask_pymongo import PyMongo
from app import app, mongo
import math
import operator
import json
from bson import json_util
from collections import defaultdict
from random import randint
from itertools import chain
#for authentication
from flask_httpauth import HTTPTokenAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
			as Serializer, BadSignature, SignatureExpired)

##################################################
auth = HTTPTokenAuth(scheme='Token')

@auth.verify_token
def verify_token(token, pwd=None):
	s = Serializer(app.config['SECRET_KEY'])
	try: data = s.loads(token)
	except SignatureExpired:
		return False
	except BadSignature:
		return False
	g.user = data
	return True
##################################################

class Root(Resource):
	def __init__(self): 
		pass
	def hash_password(self, pwd):
		return pwd_context.encrypt(pwd)
	def generate_auth_token(self, key, expiration=18000):
		s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
		return s.dumps(key)
	def post(self):
		try: name_ = request.authorization.username
		except: return make_response(jsonify({'message': \
			'No name provided.'}), 400)
		try: pwd_ = request.authorization.password
		except: return make_response(jsonify({'message': \
			'No password provided.'}), 400)
		result = mongo.db['providers'].find_one({'_id': name_})
		if result is not None:
			if result['active'] == True:
				return make_response(jsonify({'Message': 'Provider already exists'}), 409)
			else:
				h_pwd = self.hash_password(pwd_)
				mongo.db.providers.update_one({'_id': name_},
				{'$set':{
					'pwd': h_pwd,
					'active': True
					}
				})
				token = self.generate_auth_token(name_)
				return make_response(jsonify({'token':token.decode(), 
					'message':'Provider ' + name_ + ' rejoined successfully.'}), 201)
				
		h_pwd = self.hash_password(pwd_)
		rating_ = 1500
		RD_ = 350
		url = 'http://intercloud/'+name_+'/'
		mongo.db.providers.insert_one(
			{
				'_id': name_,
				#insert with hash
				'pwd': h_pwd,
				'rating': rating_,
				'RD': RD_,
				'active': True,
				'url': url
			})
		token = self.generate_auth_token(name_)
		return make_response(jsonify({'token':token.decode(), 
			'message':'Provider ' + name_ + ' joined.'}), 201)

	def get(self):
		try: name_ = request.authorization.username
		except: return make_response(jsonify({'message': \
			'No name provided.'}), 400)
		try: pwd_ = request.authorization.password
		except: return make_response(jsonify({'message': \
			'No password provided.'}), 400)
		result = mongo.db['providers'].find_one({'_id': name_, 'active': True})
		if result == None:
			return make_response(jsonify({'Message': \
			'You are not registered in the federation.'}), 404)
		h_pwd = result['pwd']
		if pwd_context.verify(pwd_, h_pwd):
			token = self.generate_auth_token(name_)		
			return make_response(jsonify({'token':token.decode(), 
			'message':'New token generated successfully.'}), 200)
		else:
			return make_response(jsonify({'message': \
			'Authentication failed.'}), 401)

	def delete(self):
		try: name_ = request.authorization.username
		except: return make_response(jsonify({'message': \
			'No name provided.'}), 400)
		try: pwd_ = request.authorization.password
		except: return make_response(jsonify({'message': \
			'No password provided.'}), 400)
		result = mongo.db['providers'].find_one({'_id': name_})
		if result == None:
			response = make_response(jsonify({'Message': \
			'Provider not found'}), 404)
		elif result['active'] == False:
			response = make_response(jsonify({'Message': \
			'Provider not found'}), 404)
		else:
			h_pwd = result['pwd']
			if pwd_context.verify(pwd_, h_pwd):
				mongo.db['providers'].update_one({'_id': name_},
					{'$unset': {'pwd':""}, '$set': {'active': False}})
				response = make_response(jsonify({'Message': \
				'Provider deregistered successfully.'}), 200)
			else: response = make_response(jsonify({'Message': 'Forbidden action.'}), 403)
		return response

	def patch(self):
		try: name_ = request.authorization.username
		except: return make_response(jsonify({'message': \
			'No name provided.'}), 400)
		try: pwd_ = request.authorization.password
		except: return make_response(jsonify({'message': \
			'No password provided.'}), 400)
		results = mongo.db['providers'].find_one({'_id': name_, 'active': True})
		if results == None:
			return make_response(jsonify({'Message': \
			'You are not registered in the federation.'}), 404)
		h_pwd = results['pwd']
		if pwd_context.verify(pwd_, h_pwd):
			content = request.json
			try: new_pwd = content['new_password']
			except: return make_response(jsonify({'message': 'New password not provided.'}), 400)
			h_pwd = self.hash_password(new_pwd)
			mongo.db['providers'].update_one(
				{'_id' : name_},
				{
				'$set' : { 'pwd' : h_pwd }
				}
				)
			return make_response(jsonify({'message': 'New password set successfully.'}), 201)
		else: return make_response(jsonify({'Message': 'Forbidden action.'}), 403)


class Records(Resource):
	def __init__(self):
		self.reqparse = reqparse.RequestParser()
		self.reqparse.add_argument('res_attr', type=dict, required=True,
		help='No proper attribute provided.', location='json')
		self.trans_table=dict.fromkeys(map(ord, ')'), None)

	@auth.login_required
	def post(self):
		args = self.reqparse.parse_args()['res_attr']
		try: name_ = args['name']
		except: return make_response(jsonify({'message': \
			'No name provided.'}), 400)
		#comment-out next line to disable auth
		#if name_ != g.user: return make_response(jsonify({'message': 'Forbidden action.'}), 403)
		try: Region = args['location']
		except: return make_response(jsonify({'message': \
			'No location provided.'}), 400)

		try: productFamily_ = args['productFamily'] 
		except: return make_response(jsonify({'message': \
			'No productFamily provided.'}), 400)

		try: instanceSize_ = args['instanceSize'] 
		except: return make_response(jsonify({'message': \
			'No instanceSize provided.'}), 400)

		try: vCPU_ = args['vCPU']
		except: return make_response(jsonify({'message': \
			'No vCPU provided.'}), 400)

		try: memory_ = args['memory']
		except: return make_response(jsonify({'message': \
			'No memory provided.'}), 400)

		try: storageInstance_ = args['storageInstance']
		except: return make_response(jsonify({'message': \
			'No storageInstance provided.'}), 400)

		try: optimization_ = args['optimization']
		except: return make_response(jsonify({'message': \
			'No optimization provided.'}), 400)

		try: OS_ = args['OS']
		except: return make_response(jsonify({'message': \
			'No OS provided.'}), 400)

		try: price_ = args['price']
		except: return make_response(jsonify({'message': \
			'No price provided.'}), 400)
	
		try: availability_ = args['availability']
		except: return make_response(jsonify({'message': \
			'No availability provided.'}), 400)

		results = mongo.db['resource_attr'].find_one(
			{'_id': name_, 'locations': {
				'$elemMatch':{  'region': Region,
						'instances': {'$elemMatch':{
								'OS': OS_,
								'instanceType':{'$elemMatch':{
									'optimization': optimization_,
									'productFamily': productFamily_,
									'instanceSize': instanceSize_}}}
								}
						}}
			})


		results = mongo.db['resource_attr'].find_one({'_id':name_})
		if results != None:
			mongo.db.resource_attr.update_one(
				{'_id':name_, 'locations':{'$not':{'$elemMatch':{'region':Region}}}},
				{'$addToSet': {'locations':{'region':Region, 'instances':[]}}})
			mongo.db.resource_attr.update_one(
				{'_id':name_, 'locations':
					{'$elemMatch':{
						'region': Region,
						'instances':
							{'$not':{'$elemMatch':{'OS': OS_}}}}}
				},
				{'$addToSet': {'locations.$.instances':{
						'OS':OS_, 
						'instanceType':[]}}
				})
			mongo.db.resource_attr.update_one(
				{'_id': name_,
				'locations.region':Region,
				'locations.instances.OS':OS_,
				},
				{'$push': {'locations.$[i].instances.$[j].instanceType': 
					{
					'optimization': optimization_,
					'productFamily': productFamily_,
					'instanceSize': instanceSize_,
					'details':{
						'price': float(price_),
						'availability': int(availability_),
						'vCPU': int(vCPU_),
						'memory' : float(memory_),
						'storageInstance': storageInstance_}}}
				},
				array_filters=[{'i.region':Region}, {'j.OS':OS_}]
				)
		else:
			mongo.db.resource_attr.insert_one(
				{'_id': name_,
				 'locations': [{'region': Region,
				 		'instances': [{ 'OS': OS_,
								'instanceType': [{ 
									'optimization': optimization_,
									'productFamily': productFamily_,
									'instanceSize': instanceSize_,
									'details':{
										'price': float(price_),
										'availability': int(availability_),
										'vCPU': int(vCPU_),
										'memory': float(memory_),
										'storageInstance': storageInstance_,
										}
									}]}]}]})
		return make_response(jsonify({'message':'Resource attributes from Provider: ' + \
		name_ + ' registered.'}), 201)

	@auth.login_required
	def delete(self):
		args = self.reqparse.parse_args()['res_attr']
		try: _name = args['name']
		except: return make_response(jsonify({'message': 'No name provided.'}), 400)
		#comment-out next line to disable auth
		#if _name != g.user: return make_response(jsonify({'message':'Forbidden action.'}), 403)
		result = mongo.db['resource_attr'].find_one({'_id': _name})
		if result is None:
			response = make_response(jsonify({'Message': \
			'Provider not found'}), 404)
			return response
		try: _region = args['location']
		except: return make_response(jsonify({'message': 'Attribute location not specified.'}), 400)
		try: _OS = args['OS']
		except: return make_response(jsonify({'message': 'Attribute OS image not specified.'}), 400)
		try: _optimization = args['optimization']
		except: return make_response(jsonify({'message': 'Attribute optimization not specified.'}), 400)
		try: _productFamily = args['productFamily']
		except: return make_response(jsonify({'message': 'Attribute productFamily not specified.'}), 400)
		try: _instanceSize = args['instanceSize']
		except: return make_response(jsonify({'message': 'Attribute instanceSize not specified.'}), 400)
		result = mongo.db['resource_attr'].update_one(
			{'_id': _name, 'locations': {'$elemMatch':{  'region': _region,'instances': {'$elemMatch':{'OS': _OS,'instanceType':{'$elemMatch':{'optimization': _optimization,'productFamily': _productFamily,'instanceSize': _instanceSize}}}}}}},
			{'$pull': {'locations.$[i].instances.$[j].instanceType': {'$and':[{'optimization': _optimization},{'productFamily': _productFamily},{'instanceSize': _instanceSize}]}}},
			array_filters=[{'i.region':_region}, {'j.OS':_OS}]
			)
		if result is not None:
			return  make_response(jsonify({'Message': 'Item Deleted'}), 200)
		else:
			return make_response(jsonify({'Message': 'Item not found'}), 400)

	@auth.login_required
	def patch(self):
		args = self.reqparse.parse_args()['res_attr']
		try: _name = args['name']
		except: return make_response(jsonify({'message': 'No name provided.'}), 400)
		#comment-out next line to disable auth
		#if _name != g.user: return make_response(jsonify({'message':'Forbidden action.'}), 403)
		result = mongo.db['resource_attr'].find_one({'_id': _name})
		if result is None:
			response = make_response(jsonify({'Message': \
			'Provider not found'}), 404)
			return response
		try: _region = args['location']
		except: return make_response(jsonify({'message': 'Attribute location not specified.'}), 400)
		try: _OS = args['OS']
		except: return make_response(jsonify({'message': 'Attribute OS image not specified.'}), 400)
		try: _optimization = args['optimization']
		except: return make_response(jsonify({'message': 'Attribute optimization not specified.'}), 400)
		try: _productFamily = args['productFamily']
		except: return make_response(jsonify({'message': 'Attribute productFamily not specified.'}), 400)
		try: _instanceSize = args['instanceSize']
		except: return make_response(jsonify({'message': 'Attribute instanceSize not specified.'}), 400)
		price_missing = False
		set_dict = {}
		try: 
			_price = args['price']
			set_dict['locations.$[i].instances.$[j].instanceType.$[k].details.price'] = float(_price)
		except: price_missing = True
		try: 
			_availability = args['availability']
			set_dict['locations.$[i].instances.$[j].instanceType.$[k].details.availability'] = int(_availability)
		except: 
			if price_missing:
				return make_response(jsonify({'message': 'Attributes price or availability not specified.'}), 400)
		result = mongo.db['resource_attr'].update_one(
			{'_id': _name, 'locations': {
				'$elemMatch':{  'region': _region,
						'instances': {'$elemMatch':{
								'OS': _OS,
								'instanceType':{'$elemMatch':{
									'optimization': _optimization,
									'productFamily': _productFamily,
									'instanceSize': _instanceSize}}}
								}
						}}
			},
			{'$set': set_dict
			},
			array_filters=[{'i.region':_region}, {'j.OS':_OS}, {'$and': [{'k.productFamily': _productFamily},{'k.instanceSize': _instanceSize}]}]
			)
		if result.matched_count != 0:
			if result.modified_count != 0:
				return  make_response(jsonify({'Message': 'Item Patched'}), 200)
			else:
				return make_response(jsonify({'Message': 'No changes to be made.'}), 200)
		else:
			return make_response(jsonify({'Message': 'Item not found'}), 400)


class Matchmaking_agent(Resource):
	def __init__(self):
		self.reqparse = reqparse.RequestParser()
		self.reqparse.add_argument('search', type=dict, required=True,
		help='No proper search.', location='json')

	#create new entry in the transaction list
	def import_data(self, pr, cl):
		#simulate random transaction result
		outcome_=randint(0,1)
		contract ={pr:{'client': cl, 'outcome':outcome_}}
		result = mongo.db['agent'].insert_one(contract)
		trans_id = result.inserted_id
		return trans_id

	#use glicko system to reduce matched providers down to one
	def match_making(self,data,low_c):
		my_dict={}
		#get matching providers' characteristics from the db
		urls = {}
		for match in data:
			results = mongo.db['providers'].find_one(
				{'_id': match}, 
				{'rating':1, 'RD':1, 'url':1, '_id':0}
			)
			urls[match] = results['url']
			dif= results['rating'] - low_c
			dif=abs(dif) 
			matching=match+'_'+str(results['RD'])
			my_dict[matching]=dif
		#fetch the provider(s) with the lowest rating difference from
		#the requesting provider's rating
		min_value=min(my_dict.values())
		result=[key for key,value in my_dict.items() if value==min_value]
		if len(result)==1:
			result,RD=result[0].split("_")
			url = [value for key,value in urls.items() if key==result]
			return result, url
		#fetch the provider(s) with the lowest RD
		my_dict={}
		for res in result:
			res,RD=res.split("_")
			my_dict[res]=float(RD)
		min_value=min(my_dict.values())
		result=[key for key,value in my_dict.items() \
				if value==min_value]
		#just fetch a random provider
		if len(result)==1:	
			url = [value for key,value in urls.items() \
				if key==result[0]]
			return result[0], url[0]
		else:
			j=len(result)-1
			i=randint(0,j)
			url = [value for key,value in urls.items() \
				if key==result[i]]
			return result[i], url[0]

	@auth.login_required
	def get(self):
		args = self.reqparse.parse_args()['search']
		#find providers which have the proper rating
		prov = mongo.db.providers.find_one(
			{'_id': g.user},
			{'rating': 1, 'RD':1}
		)
		prov_rating = prov['rating']
		prov_RD = prov['RD']
		lower_bound = prov_rating - 2*prov_RD
		upper_bound = prov_rating + 2*prov_RD
		provs = mongo.db.providers.find(
			{'rating': {'$lte':upper_bound}, 'active': True},
			{'_id':1}
		)
		_id_lst = []
		for prov in provs:
			_id_lst.append(prov['_id'])
		#search for each virtual machine
		final_results = {}
		#final_results holds results for both machines
		for _vm in args:
			vm = args[_vm]
			vm_values = {}
			tmp_id_lst = _id_lst
			tmp_loc_lst = []
			tmp_os_lst = []
			#check if number of vms requested is given
			try: vm_values['locations.instances.instanceType'
				'.details.availability'] = {'$gte': int(vm['VMnum'])}
			except: return make_response(jsonify({'Message': \
				'VMnum key missing.'}), 401)
			#check if vm characteristics define the vm properly
			try: vm_values['locations.instances.instanceType'
				'.optimization'] = vm['optimization']
			except: 
				try:
					vm_values['locations.instances.instanceType'
						'.productFamily'] = vm['productFamily']
					vm_values['locations.instances.instanceType'
						'.instanceSize'] = vm['instanceSize']
				except: return make_response(jsonify({'Message':
					'productFamily and instanceSize keys '
					'are missing or optimization key '
					'is missing.'}), 401)
			#check if mandatory characteristics are given
			try: _mandatory = vm['mandatory']
			except: return make_response(jsonify({'Message': \
				'Mandatory field missing.'}), 401)
			#construct proper dictionaries to issue the query 
			for key in _mandatory:
				if key == 'location':
					tmp_loc_lst = [_mandatory[key]]
				elif key == 'OS':
					tmp_os_lst = [_mandatory[key]]
				elif key == 'price':
					vm_values['locations.instances.instanceType'
						'.details.price'] = {'$lte':\
						float(_mandatory[key])}
				elif key == 'vCPU':
					vm_values['locations.instances.instanceType'
						'.details.vCPU'] = {'$gte': \
						float(_mandatory[key])}
				elif key == 'memory':
					vm_values['locations.instances.instanceType'
						'.details.memory'] = {'$gte':\
						float(_mandatory[key])}
				elif key == 'storageInstance':
					vm_values['locations.instances.instanceType'
					'.details.storage'
					'Instance'] = _mandatory[key]
			
			region_match = {}
			if tmp_loc_lst != []:
				region_match['locations.region'] = {'$in': tmp_loc_lst}
			os_match = {}
			if tmp_os_lst != []:
				region_match['locations.instances.OS'] = {'$in': tmp_os_lst}

			results = mongo.db.resource_attr.aggregate([
				{'$match': {'_id': {'$in': tmp_id_lst}}},
				{'$unwind':'$locations'},
				{'$match': region_match},
				{'$unwind':'$locations.instances'},
				{'$match': os_match},
				{'$unwind':'$locations.instances.instanceType'},
				{'$match': vm_values},
				{'$project': {'_id': 1, 'locations.region': 1, \
					'locations.instances.OS': 1}}
				])
			
			match_dict = {}
			for doc in results:
				try: 
					if doc['locations']['region'] not in \
					match_dict[doc['_id']]['loc_match']:
						match_dict[doc['_id']]\
						['loc_match'].append(doc['locations']\
						['region'])
					if doc['locations']['instances']['OS'] not in \
					match_dict[doc['_id']]['os_match']:
						match_dict[doc['_id']]\
						['os_match'].append(doc['locations']\
						['instances']['OS'])
				except:
					match_dict[doc['_id']] = {'loc_match': \
						[doc['locations']['region']],
						'os_match': [doc['locations']\
						['instances']['OS']]}

			#check if proper providers exist
			if match_dict == {}:
				return make_response(jsonify({'Message': 'Could not '
					'find a match.'}), 200)
			#check for optional characteristics
			try: _optional = vm['optional']
			except: _optional = {}
			#if there is only one matched provider abort 
			#optional search
			if len(match_dict) == 1:
				_optional = {}
			#proceed optional search based on the prioriterised
			#sorted characteristics
			for _key, value in sorted(_optional.items()):
				key = _key.split('.')[1]
				region_match = {}
				os_match = {}
				if key == 'location':
					region_match = {'locations.region': value}
				elif key == 'OS':
					os_match = {'locations.instances.OS': value}
				elif key == 'price':
					vm_values['locations.instances.instanceType'
					'.details.price'] = {'$lte': float(value)}
				elif key == 'vCPU':
					vm_values['locations.instances.instanceType'
					'.details.vCPU'] = {'$gte': float(value)}
				elif key == 'memory':
					vm_values['locations.instances.instanceType'
					'.details.memory'] = {'$gte': float(value)}
				elif key == 'storageInstance':
					vm_values['locations.instances.instanceType'
					'.details.storageInstance'] = value
				if region_match == {}:
					or_lst = []
					for key in match_dict:
						or_lst.append({'$and':\
							[{'_id': key}, 
							{'locations.region':\
								{'$in':\
								match_dict[key]['loc_match']}
							}]
						})
					region_match = {'$or': or_lst}
				if os_match == {}:
					or_lst = []
					for key in match_dict:
						or_lst.append({'$and':\
							[{'_id': key},
							{'locations.instances.OS':\
								{'$in':\
								match_dict[key]['os_match']}
							}]
						})
					os_match = {'$or': or_lst}
				tmp_id_list = []
				for result in match_dict:
					tmp_id_list.append(result)
				results = mongo.db.resource_attr.aggregate([
					{'$match': {'_id': {'$in': tmp_id_lst}}},
					{'$unwind':'$locations'},
					{'$match': region_match},
					{'$unwind':'$locations.instances'},
					{'$match': os_match},
					{'$unwind':'$locations.instances'
						'.instanceType'},
					{'$match': vm_values},
					{'$project': {'_id': 1, 'locations.region': 1,\
						'locations.instances.OS': 1}}
					])
				new_match_dict = {}
				for doc in results:
					try: 
						if doc['locations']['region'] not in \
						new_match_dict[doc['_id']]['loc_match']:
							new_match_dict[doc['_id']]\
							['loc_match'].append(doc['loc'
							'ations']['region'])
						if doc['locations']['instances']\
						['OS'] not in new_match_dict[doc['_id']]\
						['os_match']:
							new_match_dict[doc['_id']]\
							['os_match'].append(doc['loc'
							'ations']['instances']['OS'])
					except:
						new_match_dict[doc['_id']] = {'loc'
						'_match':\
						[doc['locations']['region']], 'os'
						'_match':\
						[doc['locations']['instances']['OS']]}
				#if there are no results, keep previous results	and 
				#abort optional search	
				if new_match_dict != {}:
					match_dict = new_match_dict
				else: break
			#hold results per virtual machine requested
			res_lst = []
			for result in match_dict:
				res_lst.append(result)
			final_results[_vm] =  res_lst
		#find the providers that can provide all the vms
		init_key = next(iter(final_results))
		final_id_list = final_results[init_key] 
		for vm in final_results:
			final_id_list = list(set(final_id_list).intersection(final_results[vm]))
		if final_results == []:
			return make_response(jsonify({'Message': \
				'No match found.'}), 200)
		#reduce to one matched provider with the help of glicko system
		if len(final_id_list) != 1:
			match, url = self.match_making(final_id_list, lower_bound)
		else:
			match = final_id_list[0]
			result = mongo.db['providers'].find_one({'_id': match},
				{'url':1, '_id':0})
			url = result['url']
		#create entry for the new impending transaction in the 
		#transaction log 
		trans_id = self.import_data(match, g.user)
		#return message informing the sender about the new transaction
		#and the identity and the url of the matched provider
		return make_response(jsonify({'Message': 'Match found.',
			'Provider name': match, 'URL': url,
			'Transaction id': str(trans_id)}), 200)
			

class Rating_Agent(Resource): #Rating agent

	def __init__(self):
		self.reqparse = reqparse.RequestParser()
		self.reqparse.add_argument('rating', type=dict, required=True,
		help='No proper data from agent.', location='json')
		self.provider=defaultdict(dict)

	@auth.login_required	
	def get(self):
		args = self.reqparse.parse_args()['rating']
		#comment-out next line to disable auth
		#if g.user != 'agent': return make_response(jsonify({'message': 'Forbidden action.'}), 403)
		json=[]
		results=mongo.db['agent'].find({},{'_id':0})
		for result in results:
			key=list(result.keys())
			key=key[0]
			prov=mongo.db['providers'].find_one({'_id':key},{'_id':0, 'rating':1, 'RD':1})
			rating= prov['rating']
			RD= prov['RD']
			key_prov=key+'_'+str(rating)+'_'+str(RD)
			client=result[key]['client']
			prov=mongo.db['providers'].find_one({'_id':client},{'_id':0, \
			'rating':1, 'RD':1})
			result[key]['rating']=prov['rating']
			result[key]['RD']=prov['RD']
			self.provider.setdefault(key_prov, []).append(result[key])
		response=self.provider
		#(otan tha to trexoume kanonika auto dn tha einai sxolio)
		#mongo.db['agent'].remove({}) 
		return response

	@auth.login_required
	def patch(self):
		args = self.reqparse.parse_args()['rating']
		#comment-out next line to disable auth
		#if g.user != 'agent': return make_response(jsonify({'message': 'Forbidden action.'}), 403)
		args=args['update']
		provider=args['provider']
		rating=args['rating']
		RD=args['RD']
		results = mongo.db['providers'].find_one({'name': provider})
		if results == {}:
			response = make_response(jsonify({'Message': \
			'Provider not found'}), 404)
			return response

		patched = False
		if rating != None:
			mongo.db['providers'].update(
				{'name' : provider},
				{
				'$set' : { 'rating' : rating }
				}
				)
			patched = True
		if RD != None:
			mongo.db['providers'].update(
				{'name' : provider},
				{
				'$set' : { 'RD' : RD }
				}
				)
			patched = True

		if patched != True:
			response = make_response(jsonify({'Message': \
			'No proper patch content provided.'}), 400)
			return response
		return make_response(jsonify({'Message' : 'Provider ' + \
		provider + ' patched successfully.'}), 200)

	@auth.login_required
	def put(self):
		args = self.reqparse.parse_args()['rating']
		#comment-out next line to disable auth
		#if g.user != 'agent': return make_response(jsonify({'message': 'Forbidden action.'}), 403)
		c= float(args['constant'])
		results=mongo.db['providers'].find({},{'_id':0})
		for result in results:
			RD_=min(math.sqrt(result['RD']**2+c**2),350)
			mongo.db['providers'].update(
				{'name':result['name']},
				{'$set': {'RD': RD_}})
		return make_response(jsonify({'Message' : 'Providers '  \
		' patched successfully.'}), 200)
		{"search":
  {"1":
    {"optimization":"General Purpose", "vCPU":"8", "memory":"30.5",
	  "storageInstance":"EBS", "VMnum":"50",
	"mandatory":{"location":"EU(London)"},
	"optional":{"1.OS":"Windows", "2.price":"2.085"}
	},
  "2":
    {"productFamily":"t4", "instanceSize":"xlarge", "VMnum": "45",
	"mandatory":{"price":"1.005"},
	"optional":{"1.location":"EU(Frankfurt)", "2.OS":"RHEL"}
	}
  }
}

{"res_attr":
	{"name": "amazon",
	"location": "Asia Pasific(Tokyo)",
	"OS": "Red Hat Enterprise Linux",
	"optimization": "Compute Optimized",
	"productFamily": "c4",
	"instanceSize": "xlarge",
	"vCPU": "4",
	"memory": "7.5",
	"storageInstance": "7.5 EBS",
	"price": "0.312",
	"availability": "63"
	}
}

