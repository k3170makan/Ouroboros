#!/usr/bin/python
import httptree
import sys
import random
from string import printable
def make_string(length=10):
	chars = list(printable)[:30]
	string =  "".join([chars[int(1 + random.random()*999)%len(chars)] for c in range(length)])
	return string
def fuzz(request):
	if request:
		request.add_header("Fuzz-header",make_string(10).strip(" "))
	return request

def dump_headers(http,direction="|||"):
	if http:
		print http.method,http.url
		for header in http.headers:
			print "%s %s = %s" % (direction,header,http.headers[header])
		
if __name__ == "__main__":
	request = httptree.Request(url=sys.argv[1])
	response = request.make_request()
	edge = httptree.Edge(request=request,response=response)
	httptree.dump_headers(request,direction=">>>")

	print "[*] found next edge..."
	request,response = edge.find_next(fuzz_func=fuzz)
	httptree.dump_headers(response,direction="<<<")
	for i in range(10):
		edge = httptree.Edge(request=request,response=response)
		request,response = edge.find_next(fuzz_func=fuzz)	
		httptree.dump_headers(response,direction="<<<")
