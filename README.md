# word_tempest

*Textual analysis of code as it being performed*

This was tested on Fedora 22 with perf installed - probably won't run on
other Linux flavors without some minor adjustments (rpm, debuginfo-install).
word_tempest.py runs the command provided as the single argument and does a textual
analysis of all programs and libraries invoked this way. The words contained
in function names, variables names, and custom type definitions are
automatically being extracted from debug symbols, and send as a JSON-encoded
array once per second to port 8080 on the local machine. (see [client/client.pde](client/client.pde))

See also [source_contents_booklet.pdf](source_contents_booklet.pdf) for documentation
of a related project from 2012 while studying at UCLA's DMA program.
