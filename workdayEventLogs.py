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
            self.ds.log('WARNING', 
                    "Response.text: " + str(response.text))
            return None
        json_response = response.json()
        return json_response

    def get_auditLogs(self):
        offset = 0 
        audit_logs = []
        json_response = self.get_auditLogsRequest(offset=offset)
        if json_response == None:
            return
        total = json_response['total']
        audit_logs += json_response['data']

        while offset < total:
            offset += self.limit
            json_response = self.get_auditLogsRequest(offset=offset)
            audit_logs += json_response['data']
            
        self.ds.log('INFO', "Received for auditLogs record count: %s of total %s" %(str(len(audit_logs)), total))

        return audit_logs

    def get_tokens(self, ssl_verify= True, proxies = None):
        auth_string = self.client_id + ':' + self.client_secret
        headers = {
                'Authorization':'Basic '+ base64.b64encode(auth_string.encode()).decode('ascii')
                }

        data = {
                'grant_type': 'refresh_token',
                'refresh_token': self.refresh_token,
               }
        #self.ds.log('INFO', "Attempting to connect to url: " + self.token_url + ' ,headers: ' + str(headers) + ' ,data: ' + str(data) + ' ,client_id: ' + self.client_id + ' ,secret: ' + self.client_secret)
        self.ds.log('INFO', "Attempting to connect to url: " + self.token_url + ' ,headers: ' + str('not included') + ' ,data: ' + str('not included') + ' ,client_id: ' + self.client_id + ' ,secret: ' + self.client_secret)
        try:
            response = requests.post(self.token_url, headers=headers, timeout=15, data=data, verify=ssl_verify, proxies = proxies)
        except Exception as e:
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return False

        if not response or response.status_code != 200:
            self.ds.log('WARNING', 
                    "Received unexpected " + str(response) + " response from Workday Server {0}.".format(
                    self.token_url))
            self.ds.log('WARNING', 
                    "Response.text: " + str(response.text))
            return False

        json_response = response.json()
        self.access_token = json_response['access_token']
        return True

    def workday_main(self): 

        self.rest_url = self.ds.config_get('workday', 'rest_url')
        self.token_url = self.ds.config_get('workday', 'token_url')
        self.state_dir = self.ds.config_get('workday', 'state_dir')
        self.refresh_token = self.ds.config_get('workday', 'refresh_token')
        self.client_id = self.ds.config_get('workday', 'client_id')
        self.client_secret = self.ds.config_get('workday', 'client_secret')

        if not self.get_tokens():
            return

        self.last_run = self.ds.get_state(self.state_dir)
        self.time_format = "%Y-%m-%dT%H:%M:%S"
        self.limit = 100
        current_time = datetime.utcnow()
        self.current_run = current_time.strftime(self.time_format)

        if self.last_run == None:
            last_run = current_time - timedelta(hours = 8)
            self.last_run = last_run.strftime(self.time_format)

        audit_logs = self.get_auditLogs()
        if audit_logs == None:
            self.ds.log('Error', "Somethign went wrong.  Check logs above")
            return
        for audit_log in audit_logs:
            self.ds.writeJSONEvent(audit_log, JSON_field_mappings = self.JSON_field_mappings)

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
