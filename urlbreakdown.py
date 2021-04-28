import json
import re
import uuid
from collections import Counter
from datetime import datetime
from urllib.parse import unquote_plus
from urllib.parse import parse_qs
from urllib.parse import parse_qsl
from urllib.parse import urlparse

class URLBreakdown:
	""" splits a URL into individual components, unescapes arguments, and performs light calculations for manual or automated analysis """
	def __init__(self, url, pguid=None, verbose=False):
		self.url = url
		self.pguid = pguid
		self.verbose = verbose
		# generate output and json objects
		self.url_ingest(self.url)
	
	#=============
	# character checkers
	#=============

	def check_all_characters_worker(self, x, y):
		""" worker function to check characters in a string, then append them to a list, then make a unique set """
		l = []
		if any(d in y for d in x):
			for d in x:
				if d in y:
					l.append(d)
		if len(l) > 0:
			try:
				l = list(set(l))
			except:
				pass
		return(l)
	
	def check_all_characters(self, x):
		""" checks for special, urlencode, and dangerous characters in a URL """
		# strings of characters to match against
		characters_to_check = [("special","!@#$%^&*()-+?_=,<>\\/\"\'`;"),("urlencode","%"),("dangerous","<>\\/\"\'`")]
		# a dictionary to hold the results
		d = {"characters":{}}
		# check characters in the query as given
		for tup in characters_to_check:
			checked = self.check_all_characters_worker(x, tup[1])
			if len(checked) > 0:
				d["characters"][tup[0]] = checked
		return(d)
	
	#=============
	# query argument checkers
	#=============
	
	def query_length_checker(self, q):
		""" splits the query 3 ways, and makes comparisons to check for abnormalities """
		n = []
		pqsl = parse_qsl(q) # arguments as found by parse_qsl
		if len(pqsl) > 0:
			if "&" in q:
				amps = q.split("&") # arguments as found by manually splitting on ampersand
				if len(pqsl) != len(amps):
					n.append("length_mismatch::query_split_len_ampersand")
			if ";" in q:
				semi = q.split(";") # arguments as found by manually splitting on semicolon
				if len(pqsl) != len(semi):
					n.append("length_mismatch::query_split_len_semicolon")
		return(n)
	
	#=============
	# notice functions
	#=============
	
	def create_notices(self, d):
		""" simple logic that creates a list of notices about potentially-abnormal string characteristics """
		d["notices"] = []
		#
		#
		# length checkers
		if d["url"]["unquoted"]["query_len"]:
			if d["url"]["query_len"] != d["url"]["unquoted"]["query_len"]:
				d["notices"].append("length_mismatch::query_len")
		#
		#
		# check query argument mismatches after being unquoted
		if d["url"]["parameters"]:
			if "original" in d["url"]["parameters"] and "unquoted" in d["url"]["parameters"]:
				for k,v in d["url"]["parameters"]["original"].items():
					if k in d["url"]["parameters"]["unquoted"]:
						#print(k)
						if v != d["url"]["parameters"]["unquoted"][k]:
							d["notices"].append("unquoted_argument_mismatch::{}".format(k))
					else:
						d["notices"].append("unquoted_argument_missing::{}".format(k))
		#
		#
		# check query length
		if d["url"]["query"]:
			d["notices"].extend(self.query_length_checker(d["url"]["query"]))
		#
		#
		# check characters
		if "characters" in d["url"]:
			if "special" in d["url"]["characters"]:
				d["notices"].append("contains_special_characters")
			if "urlencode" in d["url"]["characters"]:
				d["notices"].append("contains_urlencode_characters")
			if "dangerous" in d["url"]["characters"]:
				d["notices"].append("contains_dangerous_characters")
		#
		#
		# dot counts
		if "dot_count_domain" in d["url"]:
			if d["url"]["dot_count_domain"] != d["url"]["dot_count_url"]:
				d["notices"].append("length_mismatch::dot_count")
		#
		#
		# remove if empty
		if len(d["notices"]) == 0:
			d.pop("notices", None)
		else:
			d["notices"] = list(set(d["notices"]))
		return(d)
	
	#=============
	# cleaners
	#=============
	
	def clean_empty(self, d):
		""" recursively remove all keys with empty values, including nested ones """
		# https://stackoverflow.com/questions/27973988/python-how-to-remove-all-empty-fields-in-a-nested-dict/35263074
		if isinstance(d, dict):
			return {
				k: v 
				for k, v in ((k, self.clean_empty(v)) for k, v in d.items())
				if v
			}
		return d
	
	#=============
	# ingest handlers
	#=============
	
	def url_ingest(self, u):
		""" main worker function that parses and processes URL components """
		timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+"Z"
		guid = str(uuid.uuid4())
		u = urlparse(u)
		d = {"@timestamp":timestamp, "guid":guid, "url":{}}
		#
		#
		# add the parent guid
		if self.pguid:
			d["pguid"] = self.pguid
		#
		#
		# mostly ECS-aligned fields
		d["url"]["full"] = u.geturl()
		d["url"]["len"] = len(u.geturl())
		d["url"]["original"] = u.geturl()
		d["url"]["dot_count_url"] = u.geturl().count(".")
		d["url"]["scheme"] = u.scheme
		#d["url"]["netloc"] = u.netloc
		d["url"]["domain"] = u.netloc
		d["url"]["dot_count_domain"] = u.netloc.count(".")
		d["url"]["query"] = u.query
		d["url"]["query_len"] = len(u.query)
		d["url"]["path"] = u.path
		if len(u.params) > 0:
			d["url"]["params"] = u.params
		if len(u.fragment) > 0:
			d["url"]["fragment"] = u.fragment
		if u.username:
			d["url"]["username"] = u.username
		if u.password:
			d["url"]["password"] = u.password
		if u.port:
			d["url"]["port"] = u.port
		#
		#
		# mostly non-ECS-aligned fields
		d["url"]["unquoted"] = {}
		d["url"]["unquoted"]["query"] = unquote_plus(u.query)
		d["url"]["unquoted"]["query_len"] = len(unquote_plus(u.query))
		#
		#
		d["url"]["parameters"] = {}
		d["url"]["parameters"]["keys"] = []
		d["url"]["parameters"]["values"] = []
		d["url"]["parameters"]["original"] = parse_qs(u.query, keep_blank_values=True)
		if len(d["url"]["parameters"]["original"]) > 0:
			for k,v in d["url"]["parameters"]["original"].items():
				d["url"]["parameters"]["original"][k] = v[0]
				d["url"]["parameters"]["keys"].append(k)
				d["url"]["parameters"]["values"].append(v[0])
		else:
			d["url"]["parameters"].pop("original", None)
		#
		d["url"]["parameters"]["unquoted"] = parse_qs(unquote_plus(u.query), keep_blank_values=True)
		if len(d["url"]["parameters"]["unquoted"]) > 0:
			for k,v in d["url"]["parameters"]["unquoted"].items():
				d["url"]["parameters"]["unquoted"][k] = v[0]
				d["url"]["parameters"]["keys"].append(k)
				d["url"]["parameters"]["values"].append(v[0])
		else:
			d["url"]["parameters"].pop("unquoted", None)
		#
		#
		# remove lists of keys and values if empty
		if len(d["url"]["parameters"]["keys"]) == 0:
			d["url"]["parameters"].pop("keys", None)
		else:
			d["url"]["parameters"]["keys"] = list(set(d["url"]["parameters"]["keys"]))
		if len(d["url"]["parameters"]["values"]) == 0:
			d["url"]["parameters"].pop("values", None)
		else:
			d["url"]["parameters"]["values"] = list(set(d["url"]["parameters"]["values"]))
		#
		#
		d["url"].update(self.check_all_characters(u.query))
		d["url"]["unquoted"].update(self.check_all_characters(unquote_plus(u.query)))
		#
		#
		# combine the nested "unquoted" character arrays into the top-level one
		d["url"]["characters"] = {**d["url"]["characters"], **d["url"]["unquoted"]["characters"]}
		d["url"]["unquoted"].pop("characters", None)
		#
		#
		# parameter array if true
		if self.verbose:
			d["url"]["parameters"]["array"] = {}
			d["url"]["parameters"]["array"]["original"] = parse_qsl(u.query, keep_blank_values=True)
			d["url"]["parameters"]["array"]["unquoted"] = parse_qsl(unquote_plus(u.query), keep_blank_values=True)
			#
			#
			# build object based on character analysis here
			pattern = re.compile('\W')
			pat = pattern.sub("", u.geturl())
			cnt = dict(Counter(pat))
			d["url"]["characters"]["frequency"] = cnt
		#
		#
		# clean the object before returning
		# set all NoneType keys, if any, to an empty string
		for k,v in d["url"].items():
			if not v:
				d["url"][k] = ""
		#
		#
		# call notice functions here
		d = self.create_notices(d)
		#
		#
		# remove all keys that have empty strings
		d = self.clean_empty(d)
		#
		#
		# outputs
		self.output = d
		self.json = json.dumps(d)