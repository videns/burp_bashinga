burp_bashinga
=============

passive_checks.py

Check responses, which includes in burp scope for detailed errors.
Errors were taken from burp plugin "Error Message Checks", from different stacktraces and fuzzdb. It may lead to false-positive, so need to tune regexp
Main differ from "Error Message Checks" is that it listen every request/response made my burp, even by scanner or intruder tool. Error Message Checks do it only for passive scan
