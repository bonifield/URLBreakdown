#!/usr/bin/python3

from urlbreakdown import URLBreakdown

testurls = [
	"cnn.com",
	"https://www.youtube.com",
	"https://search.yahoo.com/search?p=google&fr=yfp-t&ei=UTF-8&fp=1&blank1=&blank2=",
	"https://www.google.com/search?client=firefox-b-1-d&q=reddit&a=%3Cscript%3Ealert%281%29%3B%3C%2Fscript%3E&%3Cscript%3Ealert%282%29%3B%3C%2Fscript%3E",
	"https://www.indeed.com/jobs?q=cyber&l=New+York%2C+NY"
	]

for t in testurls:
	u = URLBreakdown(t, pguid="1234-5678-9001", verbose=True)
	print(u.json)