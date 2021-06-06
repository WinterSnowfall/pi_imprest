#!/usr/bin/env python3
'''
@author: Winter Snowfall
@version: 1.20
@date: 06/06/2021
'''

import paramiko
import requests

class imp:
    '''An imp - a mythical creature that sometimes does things, but mostly rests'''
    
    HEADERS = {'content-type': 'application/json'}
    #default static values, should be overwritten when creating an imp
    rest_endpoint = None
    rest_timeout = 10
    ssh_timeout = 10

    def __init__(self, header, name, ip, username, password, command, expected, 
                 expected_dynamic_loading, payload_true, payload_false, pre_task, pre_task_payload):
        self.header = header
        self.name = name
        self.ip = ip
        self.username = username
        self.password = password
        self.command = command
        self.output = None
        self.errors = None
        self.expected = expected
        self.expected_dynamic_loading = expected_dynamic_loading
        self.payload_true = payload_true
        self.payload_false = payload_false
        self.pre_task = pre_task
        self.pre_task_payload = pre_task_payload
        self.last_state = None
        
    def stretch(self):
        if self.pre_task:
            if self.rest_endpoint is not None:
                if self.pre_task_payload is not None and self.pre_task_payload != '':
                    requests.post(self.rest_endpoint, json=self.pre_task_payload, headers=self.HEADERS, timeout=self.rest_timeout)
                else:
                    raise Exception('The imp can\'t stretch without a payload!')
            else:
                raise Exception('The imp can\'t stretch without an endpoint!')
        
    def do(self):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
         
        try:   
            ssh.connect(self.ip, username=self.username, password=self.password, timeout=self.ssh_timeout)
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(self.command)
            ssh_stdin.close()
            
            output = ssh_stdout.read().decode('utf-8').strip()
            self.output = output if output is not None and output != '' else None
            errors = ssh_stderr.read().decode('utf-8').strip()
            self.errors = errors if errors is not None and errors != '' else None
        except Exception:
            raise
        finally:
            ssh.close()

    def rest(self):
        if self.rest_endpoint is not None:
            if self.output == self.expected:
                self.last_state = True
                requests.post(self.rest_endpoint, json=self.payload_true, headers=self.HEADERS, timeout=self.rest_timeout)
            else:
                self.last_state = False
                requests.post(self.rest_endpoint, json=self.payload_false, headers=self.HEADERS, timeout=self.rest_timeout)
        else:
            raise Exception('Can\'t rest the imp without an endpoint!')
