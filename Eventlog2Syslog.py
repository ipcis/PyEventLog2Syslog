# python eventlog forward

## Demonstrates how to create a "pull" subscription
import win32evtlog, win32event, win32con

import time, json, xmltodict, socket

import logging, logging.handlers

time.sleep(3)


#infos
#https://gist.github.com/gjyoung1974/a68020c7a4e92b5d595ff382e1e19c20



# RFC syslog facility types:
FACILITY = {
    'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
    'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
    'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
    'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
    'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
}

# RFC log levels for syslog:
LEVEL = {
    'emerg': 0, 'alert': 1, 'crit': 2, 'err': 3,
    'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
}



def initiateSyslogConnection(host, port):
    # Open a TCP socket to the remote syslog host
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.connect((host, port))
    return s
    
	
def closeSyslogConnection(s):
    # Be sure to close the socket!
    s.close()


def syslog(s, win_evt, level=LEVEL['debug'], facility=FACILITY['syslog']):
    data = '<%d>%s %s %s %s %s' % (level + facility * 8, '1', ' win-evt', '0', '0', win_evt)
    print(data)
    s.send(data.encode())  # encode the tuple as bytes for TCP packet






#query_text='*[System[Provider[@Name="Microsoft-Windows-Winlogon"]]]'

#query_text='*[System[Provider[@Name="*"]]]'

h=win32event.CreateEvent(None, 0, 0, None)
#s=win32evtlog.EvtSubscribe('System', win32evtlog.EvtSubscribeStartAtOldestRecord, SignalEvent=h, Query=query_text)

#Microsoft-Windows-PowerShell/Operational
#s=win32evtlog.EvtSubscribe('Microsoft-Windows-PowerShell/Operational', win32evtlog.EvtSubscribeStartAtOldestRecord, SignalEvent=h, Query=None)


#SYSMON - need admin rights - reading
s=win32evtlog.EvtSubscribe('Microsoft-Windows-Sysmon/Operational', win32evtlog.EvtSubscribeStartAtOldestRecord, SignalEvent=h, Query=None)




syslog_host = '10.10.30.100'
syslog_port = 514

syslog_socket = initiateSyslogConnection(syslog_host, syslog_port)

while 1:
	while 1:
		events=win32evtlog.EvtNext(s, 10)
		if len(events)==0:
			break
		for event in events:
			print (win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml))
			syslog(syslog_socket,
                           json.dumps(xmltodict.parse(win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml))),
                           level=LEVEL['debug'], facility=FACILITY['syslog'])
		print ('retrieved %s events' %len(events))
	while 1:
		print ('waiting...')
		w=win32event.WaitForSingleObjectEx(h, 2000, True)
		if w==win32con.WAIT_OBJECT_0:
			break
