#!/usr/bin/python
from sys import argv,exit
import requests
import hashlib
"""
	Purpose to achieve here:
		- data structure that allows us to ask questions based on input paths
			i.e. pertubations on the input given to a web app at different stages
		- traverse the state graph of a web app from non-authed to authed by emulating
			data input. i.e. if we can work out the authed states,
				we can workout paths to them, we can workout whether those paths are sensical
		- beyond that not just authed states but states in general can be defined and introspected
			as realistically conforming to their assumed ontological realities. questions of
				"is this a function only admins can reach" -> would be answered by hard determining
				all the possible input paths that can reach that state


		! - implementation needs to be pluggable into burp and mitm proxy for data collection

"""
attribute_dict = {"headers"   :lambda x: x.headers,\
	 "coookies"  :lambda x: x.cookies,\
	 "data"		 :lambda x: x.data,\
	 "url"		 :lambda x: x.url,\
	 "params":lambda x: x.params,\
	 "method":lambda x: x.methods,\
	 "files":lambda x: x.files}
method_dict = {"get":requests.get,\
								  "head":requests.head,\
								  "post":requests.post,\
								  "delete":requests.delete,\
								  "put":requests.put,\
								  "options":requests.options,\
								  "patch":requests.patch} #add more method later
			
	
def dump_headers(http,direction=""):
	if http:
		try:
			print http.method,http.url
		except:
			print http.url	

		for header in http.headers:
			print "\t%s %s => %s" % (direction,header,http.headers[header])

#requires requests
#TODO need a way to hash responses uniquely enough
#TODO see if we can reuse the PreparedRequest / Request object in requests

def make_response_hash(response):
	#trying to cancel some noise
	#response.headers["Date"] = ""
	#response.headers["Set-Cookie"] = ""
	hash_string = ""
	md5h = hashlib.md5()
	if response:	
		for line in response.iter_lines(decode_unicode=True):
			if type(line) == type(u"a"):
				hash_string += line
			else:
				hash_string += line
			try:
				md5h.update(line)	
			except UnicodeEncodeError,e:
				#print type(line),len(line),line
				md5h.update(len(line)*"?")
		return md5h.hexdigest()
	else:
		return ""

class Request: 
	def __init__(self,\
						headers=dict(),\
						cookies=dict(),\
						params=dict(),
						url=dict(),\
						method="get",\
						files=dict(),\
						auth=(),\
						timeout=5,\
						proxies=dict(),\
						cert=None,\
						allow_redirects=True,
						merge_response=True):

		self.params = params
		self.attribute_dict = attribute_dict
		self.merge_response = merge_response
		self.hash = ""
		self.headers = headers
		self.cookies = cookies
		self.url = url
		self.method = method
		self.auth = auth
		self.timeout = timeout
		self.proxies = proxies
		self.cert = cert
		self.files = files
		self.allow_redirects = allow_redirects
		self.self_dict = {"headers":self.headers,\
									  "cookies":self.cookies,\
									  "method":self.method,\
									  "auth":self.auth,\
									  "timeout":self.timeout,\
									  "proxies":self.proxies,\
									  "cert":self.cert,\
									  "files":self.files,\
									  "allow_redirects":self.allow_redirects}
		self.response = None #not sent yet	
	
	def add_header(self,key,value):
		self.headers[key] = value
	def merge_headers(self,headers_dict):
		for header_name in headers_dict.headers:
			self.headers[header_name] = headers_dict.headers[header_name]
	def make_request(self):
		for attribute in self.self_dict:
			#print "[*] debug:",attribute
			if type(self.self_dict[attribute]) == type(list()) or\
				 type(self.self_dict[attribute]) == type(dict()) \
					and len(self.self_dict[attribute]) == 0:
				self.self_dict[attribute] = None

		self.response = method_dict[self.method](url=self.url,\
																	headers=self.headers,\
																	cookies=self.cookies,\
																	auth=self.auth,\
																	cert=self.cert,\
																	files=self.files,\
																	proxies=self.proxies,\
																	allow_redirects=self.allow_redirects,\
																	timeout=self.timeout)
		if self.merge_response:
			self.merge_headers(self.response.request)

		if self.response:
			self.response_id = make_response_hash(self.response)
			#print self.response_id 
		return self.response
	def hash(self):
		md5h = hashlib.md5()
		hash_string = ""
		for attribute in self.self_dict:
			_string = self.self_dict[attribute].__repr__()
			if type(_string) == type(u"a"):
				_string = _string.encode('ascii','ignore')
			else:
				if type(_string) != type(""):
					print type(_string),_string #debugging
					_string = ""
			hash_string += _string
		md5h.update(hash_string)

		self.hash = md5h.hexdigest()
	def hash_content(self):
		#make a hash of the content, we probably need to subdivide this further?
		return
	def show(self):
		doc_string = ""
		tag = ">>>"
		if self.method and self.url:
			doc_string += self.method+" "+self.url+"\n"
		if self.headers:
			for header in self.headers:
				doc_string += tag + "%s:%s\n"	% (header,self.headers[header])
		if self.params:
			doc_string += tag
			for index,param in enumerate(self.params):
				if index != len(self.params) -1:
					doc_string += "%s=%s&" % (param,self.params[param])
				else:
					doc_string += "%s=%s\n" % (param,self.params[param])
class Edge:
	def __init__(self,request,response,ttl=100):
		self.ttl = ttl #amount of times to re-request before dying in the 
		self.request = request
		self.response = response

		self.request_hash = ""
		self.response_hash = ""
		#scrap replacement stuff - stick to edge = (request,response)
		#self.edge = {self.replacement.build_json():vertex.build_json()} #using json string versions of the objects to build the dictionary
	def make_edge(self):
		
		if not self.request:
			self.request.make_request()
			self.response = self.request.response 

		#check if the reqest suceeded
		if self.response:
			self.response_hash = make_response_hash(self.response)

		if self.request:
			self.request_hash = self.request.hash()
		return self.response_id,self.request_id
	def find_next(self,fuzz_func=lambda x: x[::-1]): #fuzz stuff to get  
		#allows arb lambda's as fuzzing functions 	
		cur_request = None
		cur_response = None
		if self.response:
			cur_response = self.response
		else:
			cur_request = self.request
			cur_response = self.request.make_request()

		MAX_COUNT=100
		count = 0
		while self.response_hash == make_response_hash(cur_response):
			count += 1
			if count > MAX_COUNT:
				return None
			cur_request = fuzz_func(cur_request)
			cur_response = cur_request.make_request()
		print "[debug] old id <'%s'>, new <'%s'>" % (self.response_hash, make_response_hash(cur_response))
		return cur_request,cur_response

class HTTPTree:
	def __init__(self,response=None,\
							request=None,\
							edges=[]):
		if request and response:
			self.edges = [edge(response=response,\
											request=request)]
		elif verts:
			self.edges = edges
		else:
			raise Exception("response,request and vertices objects not provided for RequestTree init")	
	def build(self):
		self.edge_ids = [] #builds a quick list of egde id's 
		for edge in self.edges:
			if edge.response and edge.request:
				self.edge_ids.append(edge.response_id)
				self.edge_ids.append(edge.request_id)

		self.edge_ids = list(set(self.edge_ids))
	def grow(self):
		#invokes the find_next method for each edge 
		for edge in self.edges:
			edge.grow()
		
	def root(self):
		return self.edges[0]
	def add(self,request,response):
		self.edges.append(edge(response=response,\
											 request=request))

	def get_response(self):
		return self.response
	def get_request(self):
		return self.request

#dry run testing
if __name__ == "__main__":
	"""
		TODO: 1 - dry run vertex object
				2 - offload to external file
					...
				3 - build graphs
					...
				4 - draw graphs
	"""	
