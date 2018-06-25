'''
Created by: David Pereira
email: inexhero@gmail.com

'''
import urllib3
import urllib
import sys
import syslog
import os
import owncloud
def getHost():
    '''
    Get the server url from the config file on /etc/sync_os.conf
    Return None if the file doesn't exist, otherwise return the first line
    of the file as string
    '''
    try:
        conf_file = open("/etc/sync_os.conf","r")
    except:
        print ("Can't find the /etc/sync_os")
        return None
    ip = conf_file.readline()
    ip = ip.strip('\n')
    conf_file.close()
    return ip

def checkUserOnCloud(host,username,password):
    """
    Validate the user in the cloud server, if the user doesn't exist retun None,
    otherwise it will return a list with user info.
    """
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    oc = owncloud.Client(host,verify_certs=False)
    oc.login(username,password)
    try:
        user_data = oc.get_user(username)
    except:
        return None
    return  user_data
def userExistOnPc(username):
    """
    Count how many users match the username in the /etc/passwd file, and return the numbers, I expect to be only "0" or "1"
    """
    command = "/bin/grep -c '^" + username + ":' /etc/passwd"
    user_count = os.popen(command).read()
    user_count = user_count.strip('\n')
    return user_count

def createNewUser(real_name,username,password):
    """
    Create a new user in the local system.
    """
    command = "/usr/sbin/useradd " + username + " -m -s /bin/bash -c '"+real_name + "'"
    os.system(command)
    updatePassword(username,password)
    
def updatePassword(username,password):
    """
    Update the password for the username in the local system
    """
    command = "echo " +username+":"+password+" | chpasswd"
    os.system(command)

def pam_sm_authenticate(pamh,flags,argv):
    syslog.syslog ("Using nextcloud")
    # Get the password
    resp = pamh.conversation(
        pamh.Message(pamh.PAM_PROMPT_ECHO_OFF,"Password")
        )

    #Get the username
    try:
        user = pamh.get_user(None)
    except:
        return e.pam_result
    if user == None:
        return pamh.PAM_USER_UNKNOWN

    syslog.syslog("Checking info for: " + user)
    
    host_url = getHost()
    if host_url == None:
        syslog.syslog("There is a problem with the server")
        return pamh.PAM_SERVICE_ERR

    user_data = checkUserOnCloud(host_url,user,resp.resp)
    u_is_on_system = userExistOnPc(user)

    # check if the user exist in the cloud, otherwise check in the local system as last step
    if user_data != None:
        syslog.syslog(user + "Exist in the nextcloud database")
        if u_is_on_system =="1":
            updatePassword(user,resp.resp)
            syslog.syslog(user + " already exist in this pc, updating password")
            return pamh.PAM_SUCCESS
        else:
            real_name = user_data['displayname']
            syslog.syslog("Creating a new local account for: "+real_name+":"+user)
            createNewUser(real_name,user,resp.resp)
            return pamh.PAM_SUCCESS
    # check if the user exist in the system...
    else:
        syslog.syslog(user +" Not found in the nextcloud database or there is a problem with the nextcloud server")
        if u_is_on_system == "1":
            syslog.syslog(user + " Exist in the local system")
            return pamh.PAM_SUCCESS
        else:
            syslog.syslog(user + " Doesn't exist in the local system")
            return pamh.PAM_IGNORE    
        return pamh.PAM_IGNORE
    
def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS

def pam_sm_acct_mgmt(pamh, flags, argv):
    return pamh.PAM_SUCCESS

def pam_sm_open_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS

def pam_sm_close_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS

def pam_sm_chauthtok(pamh, flags, argv):
    return pamh.PAM_SUCCESS
