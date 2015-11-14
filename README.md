# parse

A simple bitcoin blockchain parser in Python 2.7

It can be easily extended to allow extraction of further data but at present allows harvesting of pubkeyhash and 
every bitcoin address ever used (contained in the .dat file and each dat file in directory..)



Things to improve:

1) work out the bug which is causing b58 encode to not prepend the version byte as a '1' for the bitcoin addresses
  it took me a long time to track this problem down when i couldn't extract valid addresses from the early script
  iterations.
