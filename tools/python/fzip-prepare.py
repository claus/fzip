#!/usr/bin/env python
"""
  Copyright (C) 2006 Claus Wahlers and Max Herkender

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

"""

import os, sys
import zlib
import StringIO
import struct

if len(sys.argv) <= 1:
	if sys.stdin.isatty():
		print "Usage: fzip-prepare.py update.zip"
		print "       fzip-prepare.py < input.zip > output.zip"
		sys.exit()
	else:
		input = sys.stdin
else:
	try:
		input = open(sys.argv[1], "rb")
	except:
		sys.exit("Input file could not be read")
output = StringIO.StringIO()
mode = 0
dict = {}
dictPos = -1
dictLen = 0

while 1:
	tmp = input.read(4)
	if tmp:
		data = struct.unpack("<I",tmp)[0]
	else:
		break
	if data == 0x04034b50:
		pos = output.tell()
		output.write(struct.pack("<I",0x04034b50))
		try:
			hdr = struct.unpack("<5H3I2H",input.read(26))
			filename = struct.unpack("<%ss" % hdr[8], input.read(hdr[8]))[0]
			extra = struct.unpack("<%ss" % hdr[9], input.read(hdr[9]))[0]
			if (hdr[1] & 0x8) == 0x08:# remove data descriptors
				tmpfile = StringIO.StringIO()
				tmplen = 0
				str = input.read(4)
				while true:
					if str == "\x08\x07\x4b\x50":
						break
					try:
						str = str[1:]+input.read()
						++tmplen
					except:
						sys.exit("File \"%s\" could not be processed: Data descriptor not found" % filename)
				datadesc = struct.unpack("<3I",input.read(12))
				if tmplen != datadesc[1]:
					sys.exit("File \"%s\" could not be processed: Bad data descriptor" % filename)
				hdr = (hdr[0],hdr[1] & 0x8,hdr[2],hdr[3],hdr[4],datadesc[0],datadesc[1],datadesc[2],hdr[8],hdr[9])
				file = tmpfile.value()
				tmpfile.close()
			else:
				file =  input.read(hdr[6])
		except:
			sys.exit("Input file is corrupted/incomplete")
		
		if (hdr[1] & 0x41) != 0x00:
			sys.exit("The entry \"%s\" is encrypted, this is not supported" % filename)
		elif (hdr[1] & 0xf7f1) != 0x00:
			sys.exit("The entry \"%s\" uses advanced features which are not supported" % filename)
		elif hdr[2] == 0x08:
			dc = zlib.decompressobj(15)
			adler32 = zlib.adler32(dc.decompress("\x78\x9c"))
			adler32 = zlib.adler32(dc.decompress(file),adler32)
			adler32 = zlib.adler32(dc.flush(),adler32)
			newextra = struct.pack("<2HI",0xdada,0x0004,adler32)
			if len(extra) > 0:
				i = 0
				while (len(extra)-i > 4):
					entry = struct.unpack("<2H",extra[i:i+4])
					if len(extra) <= i+4+entry[0]:
						if entry[1] != "\xda\xda":
							newextra += struct.pack("<2H%ss" % entry[1],entry[0],entry[1],extra[i+4:i+4+entry[1]])
						i += 4+entry[0]
					else:
						break
			extra = newextra
			extralen = len(extra)
			if extralen > 0xffff:
				extralen = 0xffff
				extra = extra[0,extralen]
			hdr = (hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5],hdr[6],hdr[7],hdr[8],extralen)
		elif hdr[2] != 0x00:
			sys.exit("The entry \"%s\" uses a form of compression which is not supported" % filename)
		
		dict[filename] = (pos,hdr,filename,extra)
		output.write(struct.pack("<5H3I2H",*hdr))
		output.write(filename)
		output.write(extra)
		output.write(file)
	elif data == 0x02014b50:
		pos = output.tell()
		output.write(struct.pack("<I",0x02014b50))
		if dictPos < 0:
			dictPos = pos
		try:
			hdr = struct.unpack("<6H3I5H2I",input.read(42))
			filename = struct.unpack("<%ss" % hdr[9], input.read(hdr[9]))[0]
			extra = struct.unpack("<%ss" % hdr[10], input.read(hdr[10]))[0]
			comment = struct.unpack("<%ss" % hdr[11], input.read(hdr[11]))[0]
		except:
			sys.exit("Input file is corrupted/incomplete")
		if dict[filename]:
			parent = dict[filename]
			mt = parent[1]
			hdr = (hdr[0],mt[0],mt[1],mt[2],mt[3],mt[4],mt[5],mt[6],mt[7],mt[8],mt[9],hdr[11],hdr[12],hdr[13],hdr[14],parent[0])
			output.write(struct.pack("<6H3I5H2I",*hdr))
			output.write(parent[2])
			output.write(parent[3])
			output.write(comment)
			dictLen += output.tell()-pos
	elif data == 0x06054b50:
		output.write(struct.pack("<I",0x06054b50))
		try:
			hdr = struct.unpack("<4H2IH",input.read(18))
			comment = struct.unpack("<%ss" % hdr[6],input.read(hdr[6]))[0]
		except:
			sys.exit("Input file is corrupted/incomplete")
		if hdr[0] != hdr[1]:
			sys.exit("The input zip is part of a series of files, this is not supported")
		hdr = (hdr[0], hdr[1], hdr[2], hdr[3], dictLen, dictPos, hdr[6])
		output.write(struct.pack("<4H2IH",*hdr))
		output.write(comment)
	else:
		break
input.close()


if len(sys.argv) <= 1:
	sys.stdout.write(output.getvalue())
else:
	try:
		outfile = open(sys.argv[1],"wb")
		outfile.write(output.getvalue())
	except:
		sys.exit("Output file could not be written to")
	outfile.close()
output.close()
