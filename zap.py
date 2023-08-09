import time
from pprint import pprint
from zapv2 import ZAPv2
import urllib

target = 'http://127.0.0.1:3456/vulnerabilities/sqli_blind/'
apiKey = 'tp4c52en8ll0p89im4eojakbr8' 

zap = ZAPv2(apikey=apiKey, proxies={'http': 'https://127.0.0.1:8080/', 'https': 'https://127.0.0.1:8080/'})
core = zap.core
sessionName = 'DVWASession'
core.new_session(name=sessionName, overwrite=True, apikey=apiKey)

contextName = "DVWA"
contextId = zap.context.new_context(contextName, apiKey)

zap.context.include_in_context(contextName, "http://127.0.0.1:3456*", apiKey) 

sessionManagement = 'cookieBasedSessionManagement'

zap.sessionManagement.set_session_management_method(
                contextid=contextId, methodname=sessionManagement,
                methodconfigparams=None, apikey=apiKey)

authMethod = 'scriptBasedAuthentication'
authScriptName = 'auth'
authScriptEngine = 'Oracle Nashorn'
authScriptFileName = 'auth.js'
authScriptDescription = 'This is a description'

# Define an authentication method with parameters for the context
auth = zap.authentication
authParams = ('scriptName=auth&'
              'LoginURL=http://127.0.0.1:3456/login.php&'
              'CSRFField=user_token&'
              'POSTData=username%3D%7B%25username%25%7D%26password%3D%7B%25password%25%7D%26Login%3DLogin%26user_token%3D%7B%25user_token%25%7D'
              )

script = zap.script
script.remove(scriptname=authScriptName, apikey=apiKey)

script.load(scriptname=authScriptName,
                            scripttype='authentication',
                            scriptengine=authScriptEngine,
                            filename=authScriptFileName,
                            scriptdescription=authScriptDescription,
                            apikey=apiKey)

pprint('Set authentication method: ' + authMethod + ' -> ' +
            auth.set_authentication_method(contextid=contextId,
                                           authmethodname=authMethod,
                                           authmethodconfigparams=authParams,
                                           apikey=apiKey))
loginindicator = '\Qlogout.php\E'
logouticator = '\Qlogin.php\E'
auth.set_logged_in_indicator(contextid=contextId,
                                        loggedinindicatorregex=loginindicator,
                                        apikey=apiKey)
auth.set_logged_out_indicator(contextid=contextId,
                                        loggedoutindicatorregex=logouticator,
                                        apikey=apiKey)
userIdList = []
userList = [
    {'name': 'Admin', 'credentials': 'Username=admin&Password=password'}
]

users = zap.users
for user in userList:
    userName = user.get('name')
    print('Create user ' + userName + ':')
    userId = users.new_user(contextid=contextId, name=userName,
                        apikey=apiKey)
    userIdList.append(userId)
    pprint('User ID: ' + userId + '; username -> ' +
                        users.set_user_name(contextid=contextId, userid=userId,
                                            name=userName, apikey=apiKey) +
                        '; credentials -> ' +
        users.set_authentication_credentials(contextid=contextId,
                            userid=userId,
                            authcredentialsconfigparams=user.get('credentials'),
                            apikey=apiKey) +
                        '; enabled -> ' +
        users.set_user_enabled(contextid=contextId, userid=userId,
                                            enabled=True, apikey=apiKey))

zap.pscan.enable_all_scanners(apikey=apiKey)
ascan = zap.ascan

print ('Accessing target %s' % target)
# try have a unique enough session...
core.access_url(url=target, followredirects=True, apikey=apiKey)

# Give the sites tree a chance to get updated
time.sleep(2)
scanPolicyName = None
forcedUser = zap.forcedUser
spider = zap.spider
ajax = zap.ajaxSpider
scanId = 0

for userId in userIdList:
        print('Starting scans with User ID: ' + userId)

        # Spider the target and recursively scan every site node found
        scanId = spider.scan_as_user(contextid=contextId, userid=userId,
                url=target, maxchildren=None, recurse=True, subtreeonly=None,
                apikey=apiKey)
        
        print('Start Spider scan with user ID: ' + userId +
                    '. Scan ID equals: ' + scanId)

        # Give the spider a chance to start
        time.sleep(2)
        while (int(spider.status(scanId)) < 100):
            print('Spider progress: ' + spider.status(scanId) + '%')
            time.sleep(2)
        print('Spider scan for user ID ' + userId + ' completed')
        '''
        # Prepare Ajax Spider scan
        pprint('Set forced user mode enabled -> ' +
                    forcedUser.set_forced_user_mode_enabled(boolean=True,
                        apikey=apiKey))
        pprint('Set user ID: ' + userId + ' for forced user mode -> ' +
                        forcedUser.set_forced_user(contextid=contextId,
                            userid=userId,
                            apikey=apiKey))
            # Ajax Spider the target URL
        pprint('Ajax Spider the target with user ID: ' + userId + ' -> ' +
                        ajax.scan(url=target, inscope=None, apikey=apiKey))
            # Give the Ajax spider a chance to start
        time.sleep(10)
        while (ajax.status != 'stopped'):
            print('Ajax Spider is ' + ajax.status)
            time.sleep(5)
        pprint('Set forced user mode disabled -> ' +
                    forcedUser.set_forced_user_mode_enabled(boolean=False,
                        apikey=apiKey))
        print('Ajax Spider scan for user ID ' + userId + ' completed')
        '''
        scanId = ascan.scan_as_user(url=target, contextid=contextId,
                userid=userId, recurse=True, scanpolicyname=scanPolicyName,
                method=None, postdata=True, apikey=apiKey)
        print('Start Active Scan with user ID: ' + userId +
                '. Scan ID equals: ' + scanId)
        # Give the scanner a chance to start
        time.sleep(2)
        while (int(ascan.status(scanId)) < 100):
            print('Active Scan progress: ' + ascan.status(scanId) + '%')
            time.sleep(2)
        print('Active Scan for user ID ' + userId + ' completed')
# Give the passive scanner a chance to finish
time.sleep(5)
# Report the results
print ('Hosts: ' + ', '.join(zap.core.hosts))
print ('Alerts: ')
pprint (zap.core.alerts())