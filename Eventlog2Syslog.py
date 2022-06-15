# python eventlog forward
#thanks to https://github.com/yarox24/attack_monitor/blob/master/installer.py

## Demonstrates how to create a "pull" subscription
import win32evtlog, win32event, win32con
import time, json, xmltodict, socket
import logging, logging.handlers

from urllib import request
import zipfile
import argparse
import shutil
import subprocess


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


def ask_question(question):
    print(question + " [Yes/y/no/n]?")
    yes = {'yes', 'y', 'ye', ''}
    no = {'no', 'n'}

    while True:
        choice = input().lower()

        if choice in yes:
            return True
        elif choice in no:
            return False
        else:
            sys.stdout.write("Please respond with 'yes' or 'no'")
	
	
	
	
def action_change_audit():

    policies_list = [("Account Management - Security Group Management", '/set /subcategory:{0CCE9235-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Account Management - User Account Management",  '/set /subcategory:{0CCE9235-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Detailed Tracking - DPAPI Activity", '/set /subcategory:{0CCE922D-69AE-11D9-BED3-505054503030} /success:enable /failure:enable' ),
                         ("Logon/Logoff - Account Lockout", '/set /subcategory:{0CCE9217-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Logon/Logoff - Logon", '/set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Logon/Logoff - Other Logon/Logoff Events", '/set /subcategory:{0CCE921C-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Account Management - User Account Management", '/set /subcategory:{0CCE9235-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Object Access - Filtering Platform Packet Drop", '/set /subcategory:{0CCE9225-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Object Access - Filtering Platform Connection", '/set /subcategory:{0CCE9226-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Object Access - Detailed File Share", '/set /subcategory:{0CCE9244-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Object Access - File Share", '/set /subcategory:{0CCE9224-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Object Access - Other Object Access Events", '/set /subcategory:{0CCE9227-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ]

    print("For following policies:")
    for policy_name, policy_cmd in policies_list:
        print("* {} : to audit success and failures".format(policy_name))

    change_policies = ask_question("Do you agree to change audit for them?")
    if change_policies:
        for policy_name, policy_cmd in policies_list:
            print("-> Changing: {}".format(policy_name))
            args = ["auditpol.exe"]
            args += policy_cmd.split(" ")
            subprocess.run(args, shell=True)
            print("")
	

def action_psaudit():
    print("You need Powershell 5 at least to enhance audit.")
    print("Your current version of PowerShell won't be checked. Assuming you had PowerShell 5.")
    print("")
    import_ps = ask_question("For Powershell 5 do you want to enable:\n* ModuleLogging\n* ScriptBlockLogging\n* Transcription to C:\\pslog")

    if import_ps:
        print("Import registry file with new settings ...")
        subprocess.run(["reg.exe", "import", POWERSHELL_ENHANCED_AUDIT_REG_FILE])
        print("=> Done")
    else:
        print("=> Skip")


#SYSMON_
SYSMON_BASE_DIR = EXTRA_FILES + "sysmon" + "\\"
SYSMON_ZIP_URL = "https://download.sysinternals.com/files/Sysmon.zip"
SYSMON_EXTRACTED_DIR = SYSMON_BASE_DIR + "extracted\\"
SYSMON_ZIP_DOWNLOADED = SYSMON_EXTRACTED_DIR + "Sysmon.zip"
SYSMON_64 = SYSMON_EXTRACTED_DIR + "Sysmon64.exe"
SYSMON_32 = SYSMON_EXTRACTED_DIR + "Sysmon.exe"
SYSMON_FAKE_NAME = SYSMON_EXTRACTED_DIR + "sysM0N.exe"
SYSMON_DRIVER = "sysM0N"
SYSMON_ED_CONFIG = SYSMON_BASE_DIR + "ed_sysmon.cfg"
SYSMON_MALWARE_CONFIG = SYSMON_BASE_DIR + "malware_sysmon.cfg"

def action_sysmon():
    install_sysmon = ask_question("Do you want to install/download pre-configured Sysmon?")

    if install_sysmon:
        # SYSMON NEEDS TO BE DOWNLOADED
        if not os.path.isfile(SYSMON_ZIP_DOWNLOADED):

            try:
                print("Downloading Sysmon ...")
                sysmon_zip_content = request.urlopen(SYSMON_ZIP_URL)
                if not sysmon_zip_content.getcode() == 200:
                    raise AssertionError
                with open(SYSMON_ZIP_DOWNLOADED, "wb") as smon:
                    print("Saving Sysmon.zip")
                    smon.write(sysmon_zip_content.read())

            except Exception as e:
                print(e)
                print("Cannot download Sysmon from URL: {}".format(SYSMON_ZIP_URL))
                print("Download Sysmon.zip manually and put in: {}".format(SYSMON_EXTRACTED_DIR))
                print("Then re-run installer.")

        if os.path.isfile(SYSMON_ZIP_DOWNLOADED):
            # EXTRACT ZIP
            if not os.path.exists(SYSMON_32) or os.path.exists(SYSMON_64):
                print("Extracting Sysmon.zip ...")
                zip_ref = zipfile.ZipFile(SYSMON_ZIP_DOWNLOADED, 'r')
                zip_ref.extractall(SYSMON_EXTRACTED_DIR)
                zip_ref.close()

            # ALREADY EXTRACTED
            if os.path.exists(SYSMON_32) and os.path.exists(SYSMON_64):
                SYSMON_TAKEN = ""

                if is_os_64_bit():
                    SYSMON_TAKEN = SYSMON_64
                else:
                    SYSMON_TAKEN = SYSMON_32

                # FAKE NAME - DOESN'T WORK
                #shutil.copy(SYSMON_TAKEN, SYSMON_FAKE_NAME)

                mode = ask_mode()
                SYSMON_CONFIG = ""
                if mode == MODE_ED:
                    SYSMON_CONFIG = SYSMON_ED_CONFIG
                else:
                    SYSMON_CONFIG = SYSMON_MALWARE_CONFIG
                print("Config choosen: {}".format(os.path.basename(SYSMON_CONFIG)))

                args = [SYSMON_TAKEN, ]
                args += "-accepteula -n -d {} -i".format(SYSMON_DRIVER).split(" ")
                args.append(SYSMON_CONFIG)

                print("Installing Sysmon (Service: {} | Driver: {})".format(os.path.basename(SYSMON_64), SYSMON_DRIVER))
                subprocess.run(args)

            else:
                print("Sysmon.zip extraction error. Extract manually")
        else:
            print("Sysmon.zip not present")


def is_os_64_bit():
    return os.path.exists("C:\\Program Files (x86)")


def downloadSysmon():
    #https://download.sysinternals.com/files/Sysmon.zip
    #download xml: https://drive.google.com/file/d/1hwH3_lf_IbBBVixuMcOdOZ2RBd5wAmjl/view?usp=sharing
    #
    # ...
	
	
def installSysmon():
    # sysmon.exe -accepteula -i sysmonconfig.xml


def setAuditPolicySettings():
    #configure audit log


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




def action_run():
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
			
			
			
def help():
    print("Security Eventlog to Syslog")
    print("Usage: python installer.py <action>")
    print("")
    print("Possible actions:")
    print("  sysmon - Install (and download) Sysmon with predefined configuration file")
    print("  auditpol - Enable more events of Windows Audit (Evtx) with auditpol.exe")
    print("  psaudit - (Require PowerShell 5) Enhance audit by enabling: ModuleLogging, ScriptBlockLogging and Transcription")

def main():
    parser = argparse.ArgumentParser(description='Installer')
    parser.add_argument('action', nargs='*', help="")
    args = parser.parse_args()
    actions_list = args.action

    #Default action install
    if len(actions_list) == 0:
        help()
    else:
        action = actions_list[0]
        if action == "sysmon":
            action_sysmon()
        elif action == "auditpol":
            action_change_audit()
        elif action == "psaudit":
            action_psaudit()
        elif action == "run":
            action_run()
        else:
            parser.error("Unknown action: {}".format(action))


if __name__ == "__main__":
   main()