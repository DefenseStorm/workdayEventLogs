#!/usr/bin/env python3

import sys,os,getopt
import traceback
import os
import fcntl
import json
import requests
from requests.auth import HTTPBasicAuth
import time
import re
from datetime import datetime, timedelta
import base64

sys.path.insert(0, './ds-integration')
from DefenseStorm import DefenseStorm

from html.parser import HTMLParser

class integration(object):

    JSON_field_mappings = {
            'systemAccount': 'client_user_name',
            'taskDisplayName': 'message',
            'ipAddress': 'client_ip',
            'userAgent': 'user_agent',
            'activityAction': 'action',
            'requestTime': 'timestamp',
            'deviceType': 'client_device_type',
            'target_descriptor': 'object_name',
            'target_id': 'object_id',
    }

    def get_auditLogsRequest(self, ssl_verify= True, proxies = None, siteId = None, groupId = None, offset = 0):
        audit_logs = []

        url = self.rest_url + '/auditLogs'
        from_time = self.last_run + 'Z'
        to_time = self.current_run + 'Z'
        print(from_time)
        print(to_time)

        headers = {
                'Authorization':'Bearer '+ self.access_token
                }

        data = {
                'type': 'userActivity',
                'to': to_time,
                'from': from_time,
                'limit': self.limit,
                'offset': offset
               }
        self.ds.log('INFO', "Attempting to connect to url: " + url + ' ,data: ' + str(data))
        try:
            response = requests.get(url, headers=headers, timeout=15, params=data, verify=ssl_verify, proxies = proxies)
        except Exception as e:
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return False

        if not response or response.status_code != 200:
            self.ds.log('WARNING', 
                    "Received unexpected " + str(response) + " response from Workday Server {0}.".format(
                    url))
            return None
        json_response = response.json()
        #print(json_response)
        return json_response

    def get_auditLogs(self):
        offset = 0 
        audit_logs = []
        json_response = self.get_auditLogsRequest(offset=offset)
        if json_response == None:
            return
        total = json_response['total']
        audit_logs += json_response['data']

        while offset <= total:
            offset += self.limit
            json_response = self.get_auditLogsRequest(offset=offset)
            audit_logs += json_response['data']
            
        print(json_response['total'])
        print(len(audit_logs))
        self.ds.log('INFO', "Results for auditLogs record count: " + str(len(audit_logs)))

        return audit_logs


    def workday_main(self): 

        self.rest_url = self.ds.config_get('workday', 'rest_url')
        self.state_dir = self.ds.config_get('workday', 'state_dir')
        self.access_token = self.ds.config_get('workday', 'access_token')

        self.last_run = self.ds.get_state(self.state_dir)
        self.time_format = "%Y-%m-%dT%H:%M:%S"
        self.limit = 100
        current_time = datetime.now()
        self.current_run = current_time.strftime(self.time_format)

        if self.last_run == None:
            last_run = current_time - timedelta(hours = 8)
            self.last_run = last_run.strftime(self.time_format)

        audit_logs = self.get_auditLogs()
        print(audit_logs[0])
        for audit_log in audit_logs:
            self.ds.writeJSONEvent(audit_log, JSON_field_mappings = self.JSON_field_mappings)
        return

        self.ds.set_state(self.state_dir, self.current_run)
        self.ds.log('INFO', "Done Sending Notifications")


    def run(self):
        try:
            pid_file = self.ds.config_get('workday', 'pid_file')
            fp = open(pid_file, 'w')
            try:
                fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError:
                self.ds.log('ERROR', "An instance of cb defense syslog connector is already running")
                # another instance is running
                sys.exit(0)
            self.workday_main()
        except Exception as e:
            traceback.print_exc()
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return
    
    def usage(self):
        print
        print(os.path.basename(__file__))
        print
        print('  No Options: Run a normal cycle')
        print
        print('  -t    Testing mode.  Do all the work but do not send events to GRID via ')
        print('        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\'')
        print('        in the current directory')
        print
        print('  -l    Log to stdout instead of syslog Local6')
        print
    
    def __init__(self, argv):

        self.testing = False
        self.send_syslog = True
        self.ds = None
    
        try:
            opts, args = getopt.getopt(argv,"htnld:",["datedir="])
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                self.usage()
                sys.exit()
            elif opt in ("-t"):
                self.testing = True
            elif opt in ("-l"):
                self.send_syslog = False
    
        try:
            self.ds = DefenseStorm('workdayEventLogs', testing=self.testing, send_syslog = self.send_syslog)
        except Exception as e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass


if __name__ == "__main__":
    i = integration(sys.argv[1:]) 
    i.run()
