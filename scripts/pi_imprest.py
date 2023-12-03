#!/usr/bin/env python3
'''
@author: Winter Snowfall
@version: 2.51
@date: 30/11/2023
'''

import paramiko
import signal
import json
import logging
from configparser import ConfigParser
from os import path
from time import time, sleep
from pi_password import password_helper
from pi_imp import imp
# uncomment for debugging purposes only
#import traceback

# conf file block
CONF_FILE_PATH = path.join('..', 'conf', 'imp_tasks.conf')

# logging configuration block
LOG_FILE_PATH = path.join('..', 'logs', 'pi_imprest.log')
logger_file_handler = logging.FileHandler(LOG_FILE_PATH, encoding='utf-8')
LOGGER_FORMAT = '%(asctime)s %(levelname)s >>> %(message)s'
logger_file_handler.setFormatter(logging.Formatter(LOGGER_FORMAT))
# logging level for other modules
logging.basicConfig(format=LOGGER_FORMAT, level=logging.ERROR)
logger = logging.getLogger(__name__)
# logging level defaults to INFO, but can be later modified through config file values
logger.setLevel(logging.INFO) # DEBUG, INFO, WARNING, ERROR, CRITICAL
logger.addHandler(logger_file_handler)

def sigterm_handler(signum, frame):
    logger.info('The imps scatter due to the dragon SIGTERM...')

    raise SystemExit(0)

def sigint_handler(signum, frame):
    logger.debug('The imps scatter due to the death knight SIGINT...')

    raise SystemExit(0)

if __name__ == "__main__":
    # catch SIGTERM and exit gracefully
    signal.signal(signal.SIGTERM, sigterm_handler)
    # catch SIGINT and exit gracefully
    signal.signal(signal.SIGINT, sigint_handler)

    # disable interpolation to allow the use of unescaped '%' in command strings
    configParser = ConfigParser(interpolation=None)

    try:
        configParser.read(CONF_FILE_PATH)

        general_section = configParser['GENERAL']
        LOGGING_LEVEL = general_section.get('logging_level').upper()

        # remains set to 'INFO' if none of the other valid log levels are specified
        if LOGGING_LEVEL == 'DEBUG':
            logger.setLevel(logging.DEBUG)
        elif LOGGING_LEVEL == 'WARNING':
            logger.setLevel(logging.WARNING)
        elif LOGGING_LEVEL == 'ERROR':
            logger.setLevel(logging.ERROR)
        elif LOGGING_LEVEL == 'CRITICAL':
            logger.setLevel(logging.CRITICAL)

        # note that the cron job mode is meant to be used primarily with ssh key authentication
        CRON_JOB_MODE = general_section.getboolean('cron_job_mode')
        REST_ENDPOINT = general_section.get('rest_endpoint')
        REST_TIMEOUT = general_section.getint('rest_timeout')
        if not CRON_JOB_MODE:
            TASK_INTERVAL = general_section.getint('task_interval')
        SSH_KEY_AUTHENTICATION = general_section.getboolean('ssh_key_authentication')
        if SSH_KEY_AUTHENTICATION:
            SSH_PRIVATE_KEY_PATH = path.expanduser(general_section.get('ssh_private_key_path'))
        SSH_TIMEOUT = general_section.getint('ssh_timeout')

    except:
        logger.critical('Could not parse configuration file. Please make sure the appropriate structure is in place!')
        raise SystemExit(1)

    if SSH_KEY_AUTHENTICATION:
        try:
            SSH_PRIVATE_KEY = paramiko.Ed25519Key.from_private_key_file(SSH_PRIVATE_KEY_PATH)
            logger.debug('Parsed SSH key using Ed25519.')
        except paramiko.ssh_exception.SSHException:
            try:
                SSH_PRIVATE_KEY = paramiko.RSAKey.from_private_key_file(SSH_PRIVATE_KEY_PATH)
                logger.debug('Parsed SSH key using RSA.')
            # paramiko supports the OpenSSH RSA private key format starting with version 2.7.1
            except paramiko.ssh_exception.SSHException:
                # can be converted with 'ssh-keygen -p -m PEM -f id_rsa'
                logger.critical('Could not parse SSH key. Either upgrade paramiko or convert your SSH key to the PEM format!')
                raise SystemExit(2)
    else:
        # read the master password from the command line
        password = input('Please enter the master password: ')

        if password == '':
            logger.critical('No password has been provided - exiting.')
            raise SystemExit(3)

        psw_helper = password_helper()

    logger.info('The imps are being summoned...')

    imp.rest_endpoint = REST_ENDPOINT
    imp.rest_timeout = REST_TIMEOUT
    imp.ssh_private_key = SSH_PRIVATE_KEY
    imp.ssh_timeout = SSH_TIMEOUT

    current_task_no = 1
    imp_tasks = []

    try:
        while True:
            # designation of the imp task
            current_task_header = f'TASK{current_task_no}'
            current_task_section = configParser[current_task_header]
            # name of the imp task
            current_task_name = current_task_section.get('name')
            # state of the imp task
            current_task_active = current_task_section.getboolean('active')
            # ip address or hostname of the remote host
            current_task_ip = current_task_section.get('ip')
            # username used for the ssh connection
            current_task_username = current_task_section.get('username')
            if not SSH_KEY_AUTHENTICATION:
                # encrypted password of the above user - use the password utilities script to get the encrypted text
                current_task_password = psw_helper.decrypt_password(password, current_task_section.get('password'))
            else:
                current_task_password = None
            # command or command list to be executed via ssh
            current_task_command = current_task_section.get('command')
            # expected output of the command
            current_task_expected = current_task_section.get('expected')
            # REST payload to be sent in case the command output matches expectations
            current_task_payload_true = json.loads(current_task_section.get('payload_true'))
            # REST payload to be sent in case the command output does not match expectations
            current_task_payload_false = json.loads(current_task_section.get('payload_false'))
            # enables/disables pre-task REST call used to signal activity
            current_task_pre_task = current_task_section.getboolean('pre_task')
            # REST payload to be sent during pre-tasks
            current_task_pre_task_payload = json.loads(current_task_section.get('pre_task_payload'))
            # time in seconds for the pre-task to run
            current_task_pre_task_duration = current_task_section.getfloat('pre_task_duration')

            imp_tasks.append(imp(current_task_header, current_task_name, current_task_active, current_task_ip,
                                 current_task_username, current_task_password, current_task_command, current_task_expected,
                                 current_task_payload_true, current_task_payload_false, current_task_pre_task,
                                 current_task_pre_task_payload, current_task_pre_task_duration))
            current_task_no += 1

    except KeyError:
        logger.info(f'Task lore parsing complete. Read {current_task_no - 1} imp tasks.')

    except:
        logger.critical('Could not parse imp task entries. Please make sure the appropriate structure is in place!')
        raise SystemExit(4)

    loopRunner = True

    try:
        while loopRunner:
            logger.info('The bell rings...')

            logger.info('***********************************************************')

            for imp in imp_tasks:
                imp_logger_prefix = f'{imp.name} >>>'

                logger.info(f'{imp_logger_prefix} The imp has awakened.')

                logger.info(f'{imp_logger_prefix} The imp is stretching...')
                try:
                    imp.stretch()
                    # pre-task sleep is deferred post imp work
                except:
                    logger.exception(f'{imp_logger_prefix} The imp has encountered an error...')
                    # uncomment for debugging purposes only
                    #logger.error(traceback.format_exc())

                if imp.active:
                    start_time = time()

                    logger.info(f'{imp_logger_prefix} The imp is working on his task...')
                    try:
                        # dynamically reload expected values when not in cron job mode
                        if not CRON_JOB_MODE:
                            configParser.read(CONF_FILE_PATH)
                            imp.expected = configParser[imp.header].get('expected')

                        imp.work()

                        logger.debug(f'{imp_logger_prefix} Imp output is: {imp.output}')
                        if imp.errors is not None:
                            logger.error(f'{imp_logger_prefix} The imp has encountered an ssh error: {imp.errors}')

                        imp.report()

                        logger.info(f'{imp_logger_prefix} [{imp.state}] is the outcome of the imp\'s task.')

                    except:
                        logger.exception(f'{imp_logger_prefix} The imp has encountered an error...')
                        # uncomment for debugging purposes only
                        #logger.error(traceback.format_exc())

                    time_delta = round(time() - start_time, 2)
                    logger.debug(f'{imp_logger_prefix} The imp has toiled for: {time_delta} seconds')
                    # see how much time we have left to wait to match the specified pre_task_duration
                    if time_delta < imp.pre_task_duration:
                        remaining_pre_task_duration = round(imp.pre_task_duration - time_delta, 2)
                        # the imp will work during pre-task then wait here a bit before it rests
                        logger.debug(f'{imp_logger_prefix} The imp must wait for: {remaining_pre_task_duration} seconds.')
                        sleep(remaining_pre_task_duration)
                    else:
                        logger.debug(f'{imp_logger_prefix} The imp has no need to wait.')

                    logger.info(f'{imp_logger_prefix} The imp has started resting...')
                    try:
                        imp.rest()
                    except:
                        logger.exception(f'{imp_logger_prefix} The imp has encountered an error...')
                        # uncomment for debugging purposes only
                        #logger.error(traceback.format_exc())
                else:
                    # we still need to wait for the pre-task duration even if the task is inactive
                    sleep(imp.pre_task_duration)

                    logger.info(f'{imp_logger_prefix} The imp will remain idle and only pretend to work...')
                    try:
                        imp.idle()
                    except:
                        logger.exception(f'{imp_logger_prefix} The imp has encountered an error...')
                        # uncomment for debugging purposes only
                        #logger.error(traceback.format_exc())

                logger.info(f'{imp_logger_prefix} The imp now sleeps.')

            logger.info('***********************************************************')

            if CRON_JOB_MODE:
                logger.info('Cron job mode enabled. The imps will now be freed.')
                loopRunner = False
            else:
                logger.info('All imps are now asleep, waiting for the bell to ring.')
                sleep(TASK_INTERVAL)

    except SystemExit:
        logger.info('The imps scatter in chaos...')

    logger.info('The imp bonds are shattered and they all flee.')
