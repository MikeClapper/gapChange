
# -*- coding: utf-8 -*-
import argparse
import json
import logging
import platform
import requests
import ssl
import sys
import time

"""
#just here for reference purposes
log levels
CRITICAL	50
ERROR	40
WARNING	30
INFO	20
DEBUG	10
NOTSET	0
"""
#######  Globals ######
args = None
content = None
dashCount = 0
findChartCalls = 0
parser = None
inCount = 0
logger = None
systemDashCount = 0
outfile = None
userDashCount = 0
version = 'A.2.0'

#############  Dashboard Specific vars ###########
auth_token = None
base_gap = 60
content = None
currentUrl = None
dashboard_info =()
dash_path="/api/v2/dashboard/"
dash_url=None
header=None
req = None
response = None
thisPage = None
topDashboard = None
topDashUrl = None

def load_args():
    global parser
    parser.add_argument("-g", help="new gap threshold in seconds (int)")
    parser.add_argument("-c", help="old gap threshold in seconds (int)")
    parser.add_argument("-l",
                        help="[DEBUG, INFO, WARNING, ERROR, CRITICAL] ")
    parser.add_argument("-u",
                        help="account URL")
    parser.add_argument("-t",
                        help="auth Token")
    parser.add_argument("-p", help="prompt Y/N for each dashboard", action="store_true")
    parser.add_argument("-T", help="trial run - log only, no mods", action="store_true")
    parser.add_argument("-j", help="dump before/after json to logfile (loglevel >= INFO)",
                        action="store_true")
    parser.add_argument("-v", help="verbose mode", action="store_true")
    parser.add_argument("-d", help="debug mode", action="store_true")

def get_page_v2(full_url, token):
    global content
    global header
    global req
    global response
    global thisPage

    header = {'Authorization': 'Bearer ' + token, "Content-Type": "application/json"}
    start_time = time.time()
    try:
        thisPage = requests.get(full_url, headers=header)
    except requests.exceptions.RequestException as e:
        print(e)
        exit(-2)

    if thisPage.status_code != 200:
        print("ERROR: http status: {}".format(thisPage.status_code))
        print("               url: {}".format(full_url))
        exit(-1)

    logging.info("get_page: url: {} - code: {} - Elapsed time: {}".format(full_url,thisPage.status_code,
                                                                          time.time() - start_time))
    dashboard = json.loads(thisPage.content).get("response")
    return dashboard

def update_dashboard(full_url,updated_dashboard):
    global auth_token
    global content
    global header
    global req
    global token

    logging.info('update_dashboard: {}  -  url: {}'.format(updated_dashboard['name'],full_url))

    start_time = time.time()
    try:
            response = requests.put(full_url, json=updated_dashboard, headers=header)
    except requests.exceptions.RequestException as e:
        print(e)
        exit(-2)

    if thisPage.status_code != 200:
        print("ERROR: http status: {}".format(thisPage.status_code))
        print("               url: {}".format(full_url))
        exit(-1)

    logging.info("get_page: url: {} - code: {} - Elapsed time: {}".format(full_url, thisPage.status_code,
                                                                          time.time() - start_time))

def findCharts(thisDash):
    global args
    global auth
    global base_gap
    global findChartCalls
    global content
    global dashCount
    global dash_info
    global systemDashCount
    global userDashCount
    chart_count = 0
    response = 'Y'
    chart_count = 0
    row_count = 0
    section_count = 0
    update_count = 0

    #full_url = topDashUrl+thisDash+"/"
    full_url = topDashUrl + thisDash
    if (args.v):
        print("full url: {}".format(full_url))

    #thisBoard = get_page(full_url, auth_token)
    thisBoard = get_page_v2(full_url, auth_token)
    dashCount += 1
    userDashCount +=1

    for section in thisBoard['sections']:
        logging.debug("section: {}  name: {}".format(section_count, section['name']))

        for row in section['rows']:
            logging.debug("section : {}   row: {} ".format(section_count, row_count))

            for thischart in row['charts']:
                logging.debug("chart name[{}]: {}".format(chart_count, thischart['name']))
                chart_count +=1
                oldgap =0
                #if (args.j):
                    #logging.info("====> Start dump - {}".format(thischart['name']))
                    #jdump = json.loads(thisPage.content).get("response")
                    #logging.info(json.dumps(thisBoard, sort_keys=True, indent=4))

                #if gap threshold exists and is 'None' or 60 - reset it to new setting.
                #if -c <int> is passed in use <int> at the base rather than 60
                #if gap threshold is set to something other than base_gap, leave it alone
                #if thischart['chartSettings'] and thischart['chartSettings'].get('type', 'line') == 'line':

                if'chartSettings' in thischart:
                    if 'expectedDataSpacing' in thischart['chartSettings']:
                        if (thischart['chartSettings'].get('expectedDataSpacing') == None):
                            #remove old tuple, add new one
                            thischart['chartSettings'].pop('expectedDataSpacing')
                            thischart['chartSettings'].update({'expectedDataSpacing':args.g})
                            logging.info("chart: {} gap: None updated to {}".format(thischart['name'],args.g))
                            update_count += 1
                        else:
                             if (int(thischart['chartSettings'].get('expectedDataSpacing')) != int(base_gap)):
                                 oldgap = thischart['chartSettings'].get('expectedDataSpacing')
                                 thischart['chartSettings'].pop('expectedDataSpacing')
                                 thischart['chartSettings'].update({'expectedDataSpacing': args.g})
                                 logging.info("chart: {} gap: {} updated to {}".format(thischart['name'], oldgap, args.g))
                                 update_count += 1
                    else:
                        #this chart didn't have a default setting
                        thischart['chartSettings'].update({'expectedDataSpacing': args.g})
                        logging.info("chart: {} gap: Undefined updated to {}".format(thischart['name'], args.g))
                        update_count += 1
                else:
                    logging.info("No chartSettings found: dashboard: {} row: {} name: {}".format(thisDash, row_count,
                                                                thischart['name']))

            row_count += 1
        section_count += 1
        row_count = 0

    if update_count:
        print("INFO: Dashboard: {} charts: {} updates: {}".format(thisDash,chart_count, update_count))
        logging.debug("full url: {}".format(full_url))

        if (args.j):
            logging.info("====> Start dump (Update) - {}".format(thisBoard['name']))
            logging.info(json.dumps(thisBoard, sort_keys=True, indent=4))

        if (args.T):
            #this is just a test run - don't update
            return(chart_count)

        if (args.p):
            #verify the user wants to update this dashboard
            #check python version for prompt method.
            if sys.version_info[0] < 3:
                response = raw_input('Do you wish to update this dashboard (Y\\n): ')
            else:
                response = input('Do you wish to update this dashboard (Y\\n): ')
            if (response.lower() == 'y' or len(response) == 0):
                update_dashboard(full_url, thisBoard)
        else:
            #just update
            update_dashboard(full_url, thisBoard)
    update_count = 0
    logging.info("Dashboard: {} charts: {} updates: {}".format(thisDash,chart_count, update_count))
    return chart_count

def get_boards(myDash):
    global topDashUrl
    global dash_info
    global thisPage
    dashcount = 0

    dash_info =[section for section in myDash["items"]]
    for thisdash in dash_info:

        #not all dashboards have "descriptions"
        if 'description' in thisdash:
            thisDescription = thisdash['description']
        else:
            thisDescription = "None"
        #System dashboards are not updated
        if thisdash['systemOwned'] == True:
            dashType = 'System'
        else:
            dashType = 'User'
            #dump user dashboard json to logs if we passed -j on command line
            if (args.j):
                logging.info("====> Start dump - {}\n".format(thisdash['name']))
                jdump = json.loads(thisPage.content).get("response")
                logging.info(json.dumps(jdump, sort_keys=True, indent=4))

        dash_info[dashcount] = {"name" : thisdash['name'],
                                "dashType" : dashType,
                                "url": thisdash['url'],
                                "description" : thisDescription,
                                "chartCount" : 0
                                }
        dashcount +=1

def main():
    global args
    global auth_token
    global base_gap
    global dashCount
    global dash_info
    global dash_url
    global inCount
    global logger
    global outfile
    global parser
    global systemDashCount
    global topDashboard
    global topDashUrl
    global userDashCount
    global wavefront_cluster

    run_start_time = time.time()
    localtime = time.asctime()

    thisPlatform = platform.platform()
    print("start time : " + localtime)
    print("Platform : {}".format(thisPlatform))
    print("Python   : {}".format(platform.python_version()))

    parser = argparse.ArgumentParser()
    load_args()
    args = parser.parse_args()

    if (args.d):
        print("Debug: true")

    if (args.l):
        logging.basicConfig(filename='gapChange.log',
                            format='%(asctime)s - %(levelname)s -     %(message)s',
                            level=args.l)
        logging.info('Starting run: Script file: %s ', sys.argv[0])
        logging.info('Command line args: {}'.format(sys.argv[1:]))
        logging.info('Script version: {}'.format(version))
        logging.info("run time : " + localtime)
        logging.info("Platform : {}".format(thisPlatform))
        logging.info("Python   : {}".format(platform.python_version()))

    if args.v: print("verbose = true")

    print("script name : {} - version: {}".format(sys.argv[0], version))

    print("runtime args: {}".format(sys.argv[1:]))
    logging.info("ssl version: {}".format(ssl.OPENSSL_VERSION))
    ssl_major, ssl_minor, ssl_fix, ssl_patch, ssl_status = ssl.OPENSSL_VERSION_INFO
    if (ssl_major) < 1:
        print('ERROR: OPENSSL version must be at least 1.x: this version:{}'.format(ssl.OPENSSL_VERSION))

    print("ssl version: {}\n".format(ssl.OPENSSL_VERSION))

    # load/log dashboard and auth token
    if (args.u):
        dash_url = args.u
    if (args.l):
        logging.info("Dashboard URL: {}".format(dash_url))
    if (args.t):
        auth_token = args.t
    if (args.c):
        base_gap = args.c

    print("Dashboard URL: {}".format(dash_url))
    print ("auth token: {}".format(auth_token))

    if (args.l):
        logging.info("auth Token: {}".format(auth_token))

    if (args.g):
        print("Base Gap Threshold: {}  New Default Gap Threshold: {}".format(base_gap, args.g))
        base_gap = args.g
        if (args.l):
            logging.info("Base Gap Threshold: {}  New Default Gap Threshold: {}".format(base_gap, args.g))
    else:
        print("\nFatal Error: You must specify a new Default Gap Threshold using -g <seconds>")
        if (args.l):
            logging.critical("New default gap threshold value not specified")
            logging.critical("Run terminated")
        exit(-1)
    logging.info("Starting to load dashboards")

    topDashUrl = dash_url + dash_path

    topDashboard = get_page_v2(topDashUrl, auth_token)
    print('Progress: analysis started')
    get_boards(topDashboard)

    for thisOne in dash_info:
        if thisOne['dashType'] == 'User':
            thisOne['chartCount'] = findCharts(thisOne['url'])
        else:
            systemDashCount += 1
            dashCount += 1
            logging.info("System Dashboard - not updated: {}".format(thisOne['name']))
        if (dashCount % 10 == 0):
            print("Progress: dashboards checked: {}".format(dashCount))
    run_time = (time.time() - run_start_time)
    print("INFO: total Dashboards: {} - System Dashboards: {}  User Dashboards: {}".format(dashCount,
                                                                                           systemDashCount,
                                                                                           userDashCount))
    print('\n\n****  User dashboards processed:')
    for thisone in dash_info:

        if thisone['dashType'] == 'User':
          print("\nName: {} - chart count: {}\nDesc: {}  \nType: {}".format(thisone['name'],
                                                           thisone['chartCount'],
                                                            thisone['description'],
                                                            thisone['dashType']))

    print("\n\nTotal run time (seconds): {:.3f} ".format(run_time))
    logging.info("Total run time (seconds): {} ".format(run_time))
if __name__ == '__main__':
    main()
logging.info('End run')
print("Normal End of Run")
sys.exit()
