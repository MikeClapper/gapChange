
# -*- coding: utf-8 -*-
import json
import traceback
import urllib
import collections
import urllib2
import requests
import jsonpickle
import os
import random
import argparse

import time
import platform
import ssl
import sys
import logging
from argparse import ArgumentParser
from Queue import Queue
from threading import Thread

import sys
from enum import Enum

#######  Globals ######
args = None
parser = None
inCount = 0
infile = None
logger = None

outfile = None
skippedLines = 0

#############  Dashboard Specific vars ###########
dashboard_results = {}
dashboard_data = {}
dashboard_info = []
total_ok = 0
total_retry = 0

#wavefront_url = 'https://try.wavefront.com'
#auth_token ='18eb4c1b-2618-4f83-9f97-543582608f58'
############## Connection info ##################

##### Mike's trial account #######
# dash_url = 'https://try.wavefront.com'
# auth_token = '18eb4c1b-2618-4f83-9f97-543582608f58'

#### pass in using -u <url> -t <token> on the command line
dash_url=None
auth_token = None

TimedResponse = collections.namedtuple('TimedResponse',
                                       'http_code',
                                        'wavefront_cluster',
                                        'content',
                                        'time_to_first_byte',
                                        'time_to_complete')

def load_args():
    global parser
    parser.add_argument("-i", help="input file file")
    parser.add_argument("-o", help="Output file")
    parser.add_argument("-l",
                        help="[DEBUG, INFO, WARNING, ERROR, CRITICAL] ")
    parser.add_argument("-u",
                        help="dashboard URL")
    parser.add_argument("-t",
                        help="auth Token")

    parser.add_argument("-v", help="verbose mode", action="store_true")
    parser.add_argument("-d", help="debug mode", action="store_true")


def timed_api_request(url_base, url_path, token, discard_content=False):
    """
    Perform a http request to Wavefront API, capture execution time and WF-specific data
    :param url_base: base URL (e.g. https://metrics.wavefront.com)
    :param url_path: url path (e.g. /api/dashboard/)
    :param token: authorization token
    :param discard_content: if False, then response_content is returned
    :return: timedresponse (tuple: http_code, wavefront_cluster, content, time_to_first_byte, time_to_complete)
    """
    logging.info("url: {}{}".format(url_base, url_path))
    req = urllib2.Request("{}{}".format(url_base, url_path))
    req.add_header('x-auth-token', token)
    start_time = time.time()
    response = urllib2.urlopen(req)
    ttfb = (time.time() - start_time) * 1000
    content = response.read()
    ttc = (time.time() - start_time) * 1000
    ret = TimedResponse(http_code=response.getcode(),
                        wavefront_cluster=response.info().getheader('x-wavefront-cluster'),
                        content=content if not discard_content else None,
                        time_to_first_byte=ttfb,
                        time_to_complete=ttc)
    return ret

def load_dashboards():
    global dashboard_results
    global dashboard_data
    global dashboard_info
    global total_ok
    global total_retry

    print "Starting loading dashboards"

    logging.info("Starting loading dashboards")
    response = timed_api_request(dash_url, "/api/dashboard/", auth_token)
    print(response)

def main():
    global args
    global auth_token
    global dashboard_results
    global dash_url
    global inCount
    global infile
    global logger
    global outfile
    global parser

    localtime = time.asctime()
    print("run time : " + localtime)
    # system, node, release, version, machine = platform.uname()
    thisPlatform = platform.platform()
    ##print('node: {}  release: {}  version: {}  machine: {}  system: {}\n'.format(node, release, version, machine, system))
    print("Platform : {}".format(thisPlatform))
    print("Processor: {}".format(platform.processor()))
    print("Python   : {}".format(platform.python_version()))
    parser = argparse.ArgumentParser()
    load_args()
    args = parser.parse_args()
    if (args.l):
        logging.basicConfig(filename='gapChange.log',
                            format='%(asctime)s - %(levelname)s -     %(message)s',
                            level=args.l)
        logging.info('Starting run: Script file: %s ', sys.argv[0])

    if args.v: print("verbose = true")

    print("script name: {}\n".format(sys.argv[0]))

    if (args.d):
        print("Debug: true")

    # load/log dashboard and auth token
    if (args.u):
        dash_url = args.u

    print("Dashboard URL: {}".format(dash_url))

    if (args.l):
        logging.info("Dashboard URL: {}".format(dash_url))
    if (args.t):
        auth_token = args.t
    print ("auth token: {}".format(auth_token))
    if (args.l):
        logging.info("auth Token: {}".format(auth_token))
    logging.info("ssl version: {}".format(ssl.OPENSSL_VERSION))
    print("ssl version: {}".format(ssl.OPENSSL_VERSION))
    load_dashboards()


if __name__ == '__main__':
    main()
logging.info('End run')
sys.exit()
