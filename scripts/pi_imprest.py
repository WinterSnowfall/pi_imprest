#!/usr/bin/env python3
'''
@author: Winter Snowfall
@version: 1.40
@date: 23/09/2021
'''

import signal
import json
import logging
from configparser import ConfigParser
from os import path
from time import sleep
from pi_password import password_helper
from pi_imp import imp
#uncomment for debugging purposes only
#import traceback

##global parameters init
configParser = ConfigParser()

##conf file block
conf_file_full_path = path.join('..', 'conf', 'imp_tasks.conf')

##logging configuration block
log_file_full_path = path.join('..', 'logs', 'pi_imprest.log')
logger_file_handler = logging.FileHandler(log_file_full_path, mode='w', encoding='utf-8')
logger_format = '%(asctime)s %(levelname)s >>> %(message)s'
logger_file_handler.setFormatter(logging.Formatter(logger_format))
#logging level for other modules
logging.basicConfig(format=logger_format, level=logging.ERROR) #DEBUG, INFO, WARNING, ERROR, CRITICAL
logger = logging.getLogger(__name__)
#logging level for current logger
logger.setLevel(logging.INFO) #DEBUG, INFO, WARNING, ERROR, CRITICAL
logger.addHandler(logger_file_handler)

def sigterm_handler(signum, frame):
    logger.info('Stopping boincmon due to SIGTERM...')
    raise SystemExit(0)

#read the master password from the command line
password = input('Please enter the master password: ')

if password == '':
    logger.critical('No password has been provided - exiting.')
    raise SystemExit(1)

logger.info('The imps are being summoned...')

try:
    #reading from config file
    configParser.read(conf_file_full_path)
    general_section = configParser['GENERAL']
    
    REST_ENDPOINT = general_section.get('rest_endpoint')
    REST_TIMEOUT = general_section.getint('rest_timeout')
    TASK_INTERVAL = general_section.getint('task_interval')
    SSH_TIMEOUT = general_section.getint('ssh_timeout')
    PRE_TASK_PAYLOAD = general_section.get('pre_task_payload')
    
except:
    logger.critical('Could not parse configuration file. Please make sure the appropriate structure is in place!')
    raise SystemExit(2)

imp.rest_endpoint = REST_ENDPOINT
imp.rest_timeout = REST_TIMEOUT
imp.ssh_timeout = SSH_TIMEOUT

psw_helper = password_helper()
imp_tasks = []
current_task_no = 1

try:
    while True:
        #designation of the imp task
        current_task_header = f'TASK{current_task_no}'
        #reading from config file
        current_task_section = configParser[current_task_header]
        #name of the imp task
        current_task_name = current_task_section.get('name')
        #ip address or hostname of the remote host
        current_task_ip = current_task_section.get('ip')
        #username used for the ssh connection
        current_task_username = current_task_section.get('username')
        #encrypted password of the above user - use the password utilities script to get the encrypted text
        current_task_password = psw_helper.decrypt_password(password, current_task_section.get('password'))
        #command or command list to be executed via ssh
        current_task_command = current_task_section.get('command')
        #expected output of the command
        current_task_expected = current_task_section.get('expected')
        #enable dynamic loading mode of expected values - true will enable a reload on each imp run
        current_task_expected_dynamic_loading = current_task_section.getboolean('expected_dynamic_loading')
        #REST payload to be sent in case the command output matches expectations
        current_task_payload_true = json.loads(current_task_section.get('payload_true'))
        #REST payload to be sent in case the command output does not match expectations
        current_task_payload_false = json.loads(current_task_section.get('payload_false'))
        #enables/disables pre-task REST call used to signal activity
        current_task_pre_task = current_task_section.getboolean('pre_task')
        #REST payload to be sent during pre-tasks
        current_task_pre_tasl_payload = json.loads(current_task_section.get('pre_task_payload'))

        imp_tasks.append(imp(current_task_header, current_task_name, current_task_ip, current_task_username, current_task_password, 
                             current_task_command, current_task_expected, current_task_expected_dynamic_loading, current_task_payload_true, 
                             current_task_payload_false, current_task_pre_task, current_task_pre_tasl_payload))
        current_task_no += 1
        
except KeyError:
    logger.info(f'Task lore parsing complete. Read {current_task_no - 1} imp tasks.')
    
#catch SIGTERM and exit gracefully
signal.signal(signal.SIGTERM, sigterm_handler)

try:
    while True:
        logger.info('The bell rings...')
        
        for imp in imp_tasks:
            logger.info('-----------------------------------------------')
            logger.info(f'The imp named {imp.name} has awakened!')
            
            logger.info(f'The imp is stretching...')
            try:
                imp.stretch()
                #the study of the arcane has shown imps must strech for at least half a second
                sleep(0.5)
                
            #halt process in case the REST endpoint can not be reached
            except ConnectionError:
                logger.critical(f'The imp could not reach REST endpoint. Terminating process.')
                raise SystemExit(3)
                
            except:
                logger.exception(f'The imp has encountered an error...')
                #logger.error(traceback.format_exc())
            
            logger.info(f'The imp is doing his task...')
            try:
                if imp.expected_dynamic_loading:
                    logger.info(f'The imp is dynamic. Reloading expected value...')                
                    #reload config file
                    configParser.read(conf_file_full_path)
                    #update imp's expected value
                    imp.expected = configParser[imp.header].get('expected')
                
                imp.do()
            
                logger.debug(f'Imp output is: {imp.output}')
                if imp.errors is not None:
                    logger.error(f'The imp has encountered an ssh error: {imp.errors}')
                    
            except:
                logger.exception(f'The imp has encountered an error...')
                #logger.error(traceback.format_exc())
            
            logger.info(f'The imp has started resting...')
            try:
                imp.rest()
                
                logger.info(f'{imp.last_state} is the outcome of the imp\'s task.')
                
            #halt process in case the REST endpoint can not be reached
            except ConnectionError:
                logger.critical(f'The imp could not reach REST endpoint. Terminating process.')
                raise SystemExit(3)
                
            except:
                logger.exception(f'The imp has encountered an error...')
                #logger.error(traceback.format_exc())
                
            logger.info('The imp now sleeps.')
            
        if len(imp_tasks) > 0:
            logger.info('-----------------------------------------------')
                
        logger.info('All imps are now asleep, waiting for the bell to ring.')
        sleep(TASK_INTERVAL)
        
except KeyboardInterrupt:
    pass
    
logger.info('The imp bonds are shattered and they all flee...')
