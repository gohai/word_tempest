#!/usr/bin/env python

# word_tempest.py
# by Gottfried Haider 2015
# licensed under GPL
#
# This was tested on Fedora 22 with perf installed - probably won't run on
# other Linux flavors without some minor adjustments (rpm, debuginfo-install).
# This runs the command provided as the single argument and does a textual
# analysis of all programs and libraries invoked this way. The words contained
# in function names, variables names, and custom type definitions are
# automatically being extracted from debug symbols, and send as a JSON-encoded
# array once per second to port 8080 on the local machine. (see client/client.pde)


import httplib
import json
import operator
import os
import signal
import subprocess
import sys
import time

if os.geteuid() != 0:
	exit("Run " + sys.argv[0] + " as root\n")

if len(sys.argv) == 1:
	exit("Usage: " + sys.argv[0] + " \"cmd\"\n")

devnull = open(os.devnull, 'wb')
tmpfile = '/tmp/word_tempest.' + str(os.getpid())

cmd = ' '.join(sys.argv[1:])
proc = subprocess.Popen(['/bin/sh', '-c', cmd])
cached_symbols = {}
install_proc = False
libs_attempted = []
num_lookups = 0


def cleanupSymbols(symbols):
	# handle underscores
	keys = symbols.keys()
	for symbol in keys:
		fields = symbol.split("_")
		if len(fields) != 1:
			for field in fields:
				if len(field) != 0:
					if field in symbols:
						symbols[field] = symbols[field] = symbols[symbol]
					else:
						symbols[field] = symbols[symbol]
			del symbols[symbol]

	# handle spaces
	keys = symbols.keys()
	for symbol in keys:
		fields = symbol.split(" ")
		if len(fields) != 1:
			for field in fields:
				if len(field) != 0:
					if field in symbols:
						symbols[field] = symbols[field] = symbols[symbol]
					else:
						symbols[field] = symbols[symbol]
			del symbols[symbol]

	# handle CamelCase
	keys = symbols.keys()
	for symbol in keys:
		i = 0
		prev = -1
		orig_symbol = symbol
		changed = False
		while i < len(symbol):
			if not symbol[i].isalpha():
				cur = 1
			elif symbol[i].islower():
				cur = 2
			else:
				cur = 3
			if prev != -1 and prev != cur:
				if not (prev == 3 and cur == 2):
					# camel potential camel case, ignore
					new_symbol = symbol[0:i]
					if new_symbol in symbols:
						symbols[new_symbol] = symbols[new_symbol] + symbols[orig_symbol]
					else:
						symbols[new_symbol] = symbols[orig_symbol]
					symbol = symbol[i:]
					i = 0
					changed = True
					#print "added " + new_symbol + " for " + orig_symbol
			prev = cur
			i = i+1
		if changed == True:
			#print "added " + symbol + " for " + orig_symbol
			if symbol in symbols:
				symbols[symbol] = symbols[symbol] + symbols[orig_symbol]
			else:
				symbols[symbol] = symbols[orig_symbol]
			del symbols[orig_symbol]

	# force lowercase
	keys = symbols.keys()
	for symbol in keys:
		if not symbol.islower():
			orig_symbol = symbol
			symbol = symbol.lower()
			if symbol in symbols:
				symbols[symbol] = symbols[symbol] + symbols[orig_symbol]
			else:
				symbols[symbol] = symbols[orig_symbol]
			del symbols[orig_symbol]

	blacklist = ['6', 'addr', 'arg', 'argc', 'args', 'argv', 'bool', 'boolean', 'byte', 'bytes', 'char', 'cpu', 'enum', 'errno', 'fd', 'file', 'glibc', 'int', 'in', 'intel', 'itoa', 'libc', 'libcs', 'long', 'main', 'memcpy', 'open', 'pmu', 'pselect', 'printf', 'selinux', 'sh', 'stdout', 'struct', 'sys', 't', 'timespec', 'uint', 'unknown', 'unsigned', 'vfs', '[', ']', '.']
	for word in blacklist:
		if word in symbols:
			del symbols[word]
	return symbols

def analyzeLibSymbol(lib, symbol):
	global cached_symbols, install_proc, libs_attempted
	global num_lookups
	if lib+"_"+symbol in cached_symbols:
		return cached_symbols[lib+"_"+symbol]
	if lib == 'kernel.kallsyms':
		# installed kernel-debug, still not working
		#args = ['/usr/bin/perf', 'probe', '-V', symbol, '--externs']
		return {}
	else:
		args = ['/usr/bin/perf', 'probe', '-x', lib, '-V', symbol, '--externs']
	# don't look up more than 25 symbols per captured sample
	# we still get to all of them over time as the cache fills up
	if num_lookups > 25:
		return {}
	num_lookups = num_lookups + 1
	analyzer = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	txt = analyzer.communicate()
	analyzer.wait()
	if analyzer.returncode == 254 and "has no debug information" in txt[1] and lib not in libs_attempted:
		#print "Trying to get debug information for " + lib
		if install_proc == False or install_proc.poll() is not None:
			#print "Getting package name"
			# get the package name
			install_proc = subprocess.Popen(['/usr/bin/rpm', '-qf', lib], stdout=subprocess.PIPE, stderr=devnull)
			install_txt = install_proc.communicate()[0]
			install_proc.wait()
			#print "Got package name"
			if install_proc.returncode == 0:
				# install the package
				pkg = install_txt.strip()
				#print "Getting debug symbols for " + pkg
				install_proc = subprocess.Popen(['/usr/bin/debuginfo-install', '-y', pkg], stdout=devnull, stderr=devnull)
				# tell caller to try again (no caching)
				return {}
			else:
				libs_attempted.append(lib)
		else:
			#print "Busy"
			# download in progress
			return {}
	if analyzer.returncode != 1:
		cached_symbols[lib+"_"+symbol] = {}
		return {}
	symbols = {}
	lines = iter(txt[0].splitlines())
	for line in lines:
		fields = line.split("\t")
		if (len(fields) != 4):
			continue
		name = fields[-1]
		if name in symbols:
			symbols[name] = symbols[name] + 1
		else:
			symbols[name] = 1
		var_type = fields[-2]
		var_type = var_type.replace('*', '')
		var_type = var_type.replace('struct ', '')
		var_type = var_type.replace('union ', '')
		var_type = var_type.replace('(', '')
		var_type = var_type.replace(')', '')
		# save the type in the symbols list
		if var_type in symbols:
			symbols[var_type] = symbols[var_type] + 1
		else:
			symbols[var_type] = 1
	# cache the symbols established
	symbols = cleanupSymbols(symbols)
	cached_symbols[lib+"_"+symbol] = symbols
	return symbols

def analyzePerfOut(out):
	global num_lookups
	num_lookups = 0
	symbols = {}
	lines = iter(out.splitlines())
	for line in lines:
		fields = line.split(' ')
		if fields[0] != "\t":
			continue
		lib = fields[-1].strip('()[]')
		# kernel.kallsyms is kernel, everything else should be an absolut path
		# sometimes "unknown"
		func = fields[-2]
		# sometimes "[unknown]"
		new_symbols = analyzeLibSymbol(lib, func)
		for symbol in new_symbols:
			if symbol in symbols:
				symbols[symbol] = symbols[symbol] + new_symbols[symbol]
			else:
				symbols[symbol] = new_symbols[symbol]
		# add the function name too
		new_symbols = cleanupSymbols({func: 1})
		for symbol in new_symbols:
			if symbol in symbols:
				symbols[symbol] = symbols[symbol] + new_symbols[symbol]
			else:
				symbols[symbol] = new_symbols[symbol]
	return symbols


# this is the main loop
while proc.poll() is None:
	try:
		recorder = subprocess.Popen(['/usr/bin/perf', 'record', '-p', str(proc.pid), '-o', '/tmp/word_tempest.' + str(os.getpid()), '-g'], stdout=devnull, stderr=devnull)
		# sample one second
		time.sleep(1)
		recorder.send_signal(signal.SIGINT)
		recorder.wait()
		if recorder.returncode != -2:
			# error
			continue
		analyzer = subprocess.Popen(['/usr/bin/perf', 'script', '-i', tmpfile], stdout=subprocess.PIPE, stderr=devnull)
		txt = analyzer.communicate()[0]
		analyzer.wait()
		os.remove(tmpfile)
		if analyzer.returncode != 0:
			# error
			continue
		symbols = analyzePerfOut(txt)
		#sorted_symbols = sorted(symbols.items(), key=operator.itemgetter(1))
		#print json.dumps(sorted_symbols)
		try:
			# write to file
			#f = open('out.json', 'a');
			#f.write(json.dumps(symbols)+",\n")
			#f.close()
			# send to port 8080 on localhost
			conn = httplib.HTTPConnection("127.0.0.1", 8080)
			conn.request("POST", "/word_tempest", json.dumps(symbols))
			response = conn.getresponse()
		except:
			pass
	except KeyboardInterrupt:
		proc.kill()

try:
	os.remove(tmpfile)
except OSError:
	pass

exit(proc.returncode)
