# -*- coding: utf-8 -*-
__author__ = 'videns'

import code
import re
import array
from burp import IBurpExtender, IScannerInsertionPointProvider, IScannerInsertionPoint, IParameter, IScannerCheck, IScanIssue, IHttpService, IHttpListener


scope_only = True
errors = [r'\.php on line [0-9]+',
        r'Fatal error:',
        r'\.php:[0-9]+',
        r'\[(ODBC SQL Server Driver|SQL Server)\]',
        r'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near',
        r'\.java:[0-9]+',
        r'\.java\((Inlined )?Compiled Code\)',
        r'[A-Za-z\.]+\(([A-Za-z0-9, ]+)?\) \+[0-9]+',
        r'at (\/[A-Za-z0-9\\.]+)*\.pm line [0-9]+',
        r'File \"[A-Za-z0-9\-_\./]*\", line [0-9]+, in',
        r'in [^\s]\.cs:[0-9]+', #aspnet
        r'\.rb:[0-9 ]+:in ', #ruby
        r'[\w\/]+\.js:[0-9]+:[0-9]+' #nodejs
        #next search strings are taken from fuzzdb
        r'A syntax error has occurred',
        r'ADODB.Field error',
        r'ASP.NET is configured to show verbose error messages',
        r'ASP.NET_SessionId',
        r'Active Server Pages error',
        r'An illegal character has been found in the statement',
        r'An unexpected token "END-OF-STATEMENT" was found',
        r'CLI Driver',
        r'Can\'t connect to local',
        r'Custom Error Message',
        r'DB2 Driver',
        r'DB2 Error',
        r'DB2 ODBC',
        r'Died at',
        r'Disallowed Parent Path',
        r'Error Diagnostic Information',
        r'Error Message : Error loading required libraries.',
        r'Error Report',
        r'Error converting data type varchar to numeric',
        r'Fatal error',
        r'Incorrect syntax near',
        r'Index of',
        r'Internal Server Error',
        r'Invalid Path Character',
        r'Invalid procedure call or argument',
        r'Invision Power Board Database Error',
        r'JDBC Driver',
        r'JDBC Error',
        r'JDBC MySQL',
        r'JDBC Oracle',
        r'JDBC SQL',
        r'Microsoft OLE DB Provider for ODBC Drivers',
        r'Microsoft VBScript compilation error',
        r'Microsoft VBScript error',
        r'MySQL Driver',
        r'MySQL Error',
        r'MySQL ODBC',
        r'ODBC DB2',
        r'ODBC Driver',
        r'ODBC Error',
        r'ODBC Microsoft Access',
        r'ODBC Oracle',
        r'ODBC SQL',
        r'ODBC SQL Server',
        r'OLE/DB provider returned message',
        r'ORA-0',
        r'ORA-1',
        r'Oracle DB2',
        r'Oracle Driver',
        r'Oracle Error',
        r'Oracle ODBC',
        r'PHP Error',
        r'PHP Parse error',
        r'PHP Warning',
        r'Parent Directory',
        r'Permission denied: \'GetObject\'',
        r'PostgreSQL query failed: ERROR: parser: parse error',
        r'SQL Server Driver\]\[SQL Server',
        r'SQL command not properly ended',
        r'SQLException',
        r'Supplied argument is not a valid PostgreSQL result',
        r'Syntax error in query expression',
        r'The error occurred in',
        r'The script whose uid is',
        r'Type mismatch',
        r'Unable to jump to row',
        r'Unclosed quotation mark before the character string',
        r'Unterminated string constant',
        r'Warning: Cannot modify header information - headers already sent',
        r'Warning: Supplied argument is not a valid File-Handle resource in',
        r'Warning: mysql_query()',
        r'Warning: pg_connect(): Unable to connect to PostgreSQL server: FATAL',
        r'You have an error in your SQL syntax near',
        r'data source=',
        r'detected an internal error \[IBM\]\[CLI Driver\]\[DB2/6000\]',
        r'include_path',
        r'invalid query',
        r'is not allowed to access',
        r'missing expression',
        r'mySQL error with query',
        r'mysql error',
        r'on MySQL result index',
        r'on line',
        r'server at',
        r'server object error',
        r'supplied argument is not a valid MySQL result resource',
        r'unexpected end of SQL command']

error_regexp = [re.compile(x, re.IGNORECASE) for x in errors]

version = "0.0.5"
class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, this_callbacks):
        global callbacks
        callbacks = this_callbacks

        callbacks.setExtensionName("passive checks")

        callbacks.registerHttpListener(HTTPListener(callbacks))

        print "Successfully loaded checks v" + version

        return


class HTTPListener(IHttpListener):
    def __init__(self, callbacks):
        self._helpers = callbacks.getHelpers()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest == 0:
            url = self._helpers.analyzeRequest(messageInfo).getUrl()
            if (not scope_only) or (scope_only and callbacks.isInScope(url)):
                response = self._helpers.analyzeResponse(messageInfo.getResponse())
                if response.getStatusCode() == 404:
                    return
                raw_response = self._helpers.bytesToString(messageInfo.getResponse())
                for one_error_regexp in error_regexp:
                    match = one_error_regexp.search(raw_response)
                    if match:
                        match_res = match.group(0)
                        start_pos = raw_response.find(match_res)
                        markers = [array.array('i', [start_pos, start_pos + len(match_res)])]
                        new_messages = callbacks.applyMarkers(messageInfo, None, markers)
                        callbacks.addScanIssue(CustomScanIssue(messageInfo.getHttpService(),
                                                               url,
                                                               [new_messages],
                                                               "Detailed error",
                                                               "Detailed error found, <b>%s</b>" % match_res,
                                                               "Firm",
                                                               "High"))


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, confidence, severity):
        self._http_service = httpService
        self._url = url
        self._http_messages = httpMessages
        self._name = name
        self._detail = detail + '<br/><br/><div style="font-size:8px">This issue was reported by Passive Checks Plugin</div>'
        self._severity = severity
        self._confidence = confidence
        return

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 134217728

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service