'''
Created by: David Pereira
email: inexhero@gmail.com

'''
from xml.etree import ElementTree
import urllib3
import requests
from requests.auth import HTTPBasicAuth
# import sys
import syslog
import os


def getHost():
    '''
    Get the server url from the config file on /etc/sync_os.conf
    Return None if the file doesn't exist, otherwise return the first line
    of the file as string
    '''
    try:
        conf_file = open("/etc/sync_os.conf", "r")
    except:
        syslog.syslog("/etc/sync_os file not found")
        return None
    ip = conf_file.readline()
    ip = ip.strip('\n')
    conf_file.close()
    return ip


def checkUserOnCloud(host, username, password):
    """
    make a request to the server; try to login
    if the server is offline return None
    else return the xml as Elementtree object
    """
    # URI to validate the login
    url = host+'/ocs/v1.php/cloud/users/'+username
    urllib3.disable_warnings()
    try:
        response = requests.get(url,
                                headers={'OCS-APIRequest': 'true'},
                                auth=HTTPBasicAuth(username, password),
                                verify=False)
        # parse the xml content
        tree = ElementTree.fromstring(response.content)
        # return the xml content
        return tree
    # If connection failed throw a error
    except requests.ConnectionError:
        syslog.syslog("Failed to connect with the server")
        return None


def status_response(res_xml=ElementTree):
    """Check for the status response in the xml file
    retriver, convert to 1 is the login has been successful
    or 0 if username or password are incorrect; return None
    if there is a problem with the server connection"""

    # Check if the xml file is empty
    if res_xml is not None:
        # Check for the status tag
        status = res_xml[0][0].text
        # Wrong credentianls
        if status == 'failure':
            return -1
        # Everthing is ok :)
        if status == 'ok':
            return 1
    else:
        return None


def displayname_response(res_xml=ElementTree):
    """Get the fullname in from the xml file
    Return 0 if there was a problem with the server request
    otherwise return a string, if the displayname tag is empty
    return the username"""
    if res_xml is not None:
        # Get the name from the xml file
        display_name = res_xml[1][11].text
        if display_name is None:
            display_name = res_xml[1][1]
        return display_name
    else:
        return 0


def userExistOnPc(username):
    """
    Count how many users match the username in the /etc/passwd file, and return the numbers, I expect to be only "0" or "1"
    """
    command = "/bin/grep -c '^" + username + ":' /etc/passwd"
    user_count = os.popen(command).read()
    user_count = user_count.strip('\n')
    return user_count


def createNewUser(real_name, username, password):
    """
    Create a new user in the local system.
    """
    command = "/usr/sbin/useradd " + username + " -m -s /bin/bash -c '" + real_name + "'"
    os.system(command)
    updatePassword(username, password)


def updatePassword(username, password):
    """
    Update the password for the username in the local system
    """
    command = "echo " + username + ":" + password+" | chpasswd"
    os.system(command)


def pam_sm_authenticate(pamh, flags, argv):
    syslog.syslog("Try to authenticate with nextcloud server")
    # Get the password
    resp = pamh.conversation(
        pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "Password")
        )

    # Get the username
    try:
        user = pamh.get_user(None)
    except:
        return e.pam_result
    if user is None:
        return pamh.PAM_USER_UNKNOWN

    syslog.syslog("Checking info for: " + user)

    host_url = getHost()
    if host_url is None:
        # The conf file do not exists in the system
        # The next pam module will try to login with the local user if exists
        return pamh.PAM_SUCCESS

    user_data = checkUserOnCloud(host_url, user, resp.resp)
    status_code = status_response(user_data)
    real_name = displayname_response(user_data)
    u_is_on_system = userExistOnPc(user)

    # Check if the server return a response
    if status_code is not None:
        # Credentianls are valid
        if status_code:
            # User exists in the local system
            if u_is_on_system == "1":
                updatePassword(user, resp.resp)
                syslog.syslog("Updating password for user: " + user)
                return pamh.PAM_SUCCESS
            # First time login in the local pc
            else:
                syslog.syslog("Creating a new local account for: " + real_name)
                createNewUser(real_name, user, resp.resp)
                return pamh.PAM_SUCCESS
        # Invalid credentianls
        else:
            syslog.syslog("Invalid credentials")
            return pamh.PAM_USER_UNKNOWN
    # Connection Error with the nextcloud server, check for the local database
    else:
        syslog.syslog("Unable to connect with the server, checking user in the local database")
        return pamh.INGONE


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
