# Introduction #

The current python-ntlm trunk code supports writing clients connecting to a server.

[Issue 4](https://code.google.com/p/python-ntlm/issues/detail?id=4) is about being able to write server-side code that will authenticate clients.

Work has been done on this in the [clientserver branch](http://python-ntlm.googlecode.com/svn/branches/clientserver/).
This now has:
  * Support for NTLM version 1 and version 2
  * Support for client and server operation
  * A sample server that can be used for testing
  * A large number of tests, which all pass

This amounts to a large rewrite of sections of the code, so we need to
clean things up and discuss how/if this could be merged onto trunk.
