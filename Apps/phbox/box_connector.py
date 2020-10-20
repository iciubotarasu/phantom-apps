#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# Usage of the consts file is recommended
# from box_consts import *
import os, ast, json
from boxsdk import OAuth2
from boxsdk import Client
import sqlite3
from sqlite3 import Error
from os import path
from datetime import datetime

class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))

class BoxConnector(BaseConnector):
    def __init__(self):
        super(BoxConnector, self).__init__()
        self._state = None
        self._base_url = None

    def _create_sql_connection(self):
        global conn
        asset_id = self.get_asset_id()
        app_dir = os.path.split(__file__)[0]
        app_id = (app_dir.split('/')[-1].split('_')[-1])
        app_state_location = '/opt/phantom/local_data/app_states/{0}/{1}_box_tokens.db'.format(app_id,asset_id)
        conn = None
        db_exist = path.exists(app_state_location)
        if db_exist:
            try:
                conn = sqlite3.connect(app_state_location)
            except Error as e:
                print(e)
        else:
            create_table_sql = '''CREATE TABLE IF NOT EXISTS box (id integer PRIMARY KEY AUTOINCREMENT,
                                                token text NOT NULL,refresh_token text NOT NULL,date text);'''
            try:
                conn = sqlite3.connect(app_state_location)
                c = conn.cursor()
                c.execute(create_table_sql)
            except Error as e:
                print(e)
        return conn

    def _store_tokens(self, access_token, refresh_token):
        self.debug_print('BOX tokens store:{},{} '.format(access_token, refresh_token))
        self._create_sql_connection()
        self.debug_print('BOX 1')
        date = datetime.now().strftime("%Y-%m-%d %I:%M:%S %p %Z")
        self.debug_print('BOX 2')
        data = [access_token, refresh_token, date]
        self.debug_print('BOX 3')
        sql = '''INSERT INTO box(token,refresh_token,date) VALUES(?,?,?);'''
        self.debug_print('BOX 4')
        cur = conn.cursor()
        self.debug_print('BOX 5')
        cur.execute(sql, data)
        self.debug_print('BOX 6')
        conn.commit()
        self.debug_print('BOX 7')
        conn.close()
        self.debug_print('BOX 8')
        return

    def _read_tokens(self):
        self._create_sql_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM box ORDER BY id DESC LIMIT 1;")
        rows = cur.fetchall()
        auth_token = rows[0][1]
        refresh_token= rows[0][2]
        conn.close()
        self.debug_print('BOX tokens read:{},{} '.format(auth_token, refresh_token))
        return auth_token, refresh_token

    def _authenticate(self):
        global client
        config = self.get_config()
        client_id = config['client_id']
        client_secret = config['client_secret']
        access_token, refresh_token = self._read_tokens()
        oauth = OAuth2(
                client_id=client_id,
                client_secret=client_secret,
                access_token=access_token,
                refresh_token=refresh_token,
                store_tokens=self._store_tokens,
            )
        client = Client(oauth)
        return client


    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to Box")
        config = self.get_config()
        access_token = config['initial_token']
        refresh_token = config['initial_refresh_token']
        self._authenticate()
        try:
            current_user = client.user(user_id='me').get()
        except:
            self._store_tokens(access_token, refresh_token)
            self.save_progress("Initial Tokens were stored.")
            self._authenticate()
        try:
            current_user = client.user(user_id='me').get()
            if current_user.name:
                self.save_progress("Connected to BOX")
                #self.save_progress("Test Conectivity will fail after the first hour of the newly generated token, but the app stores the tokens and will continue to run. If the app is not used for more than 60 days, you'll have to redo the Test Conectivity with new tokens in the app config")
                self.save_progress("Test Connectivity Passed.")
                return action_result.set_status(phantom.APP_SUCCESS, 'Connection established and tokens stored.')
        except Exception as e:
            self.debug_print('BOX error: ', str(e))
            self.save_progress("Test Connectivity Failed. {}".format(str(e)))
            self.save_progress("If you haven't used the app in the last 60 days please use the Test Conectivity with newly generated tokens.")
            self.save_progress("Please check if tokens were changed and update them into the app config.")
            return action_result.set_status(phantom.APP_ERROR, 'Connection established and tokens stored.')

    def _handle_refresh_token(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        self._authenticate()
        try:
            current_user = client.user(user_id='me').get()
            self.save_progress('Box User: {}'.format(current_user.name))
            self.save_progress('Tokens refreshed successfully')
            return action_result.set_status(phantom.APP_SUCCESS, 'Successfully refreshed tokens')
        except Exception as e:
            self.debug_print('BOX error: ', str(e))
            self.save_progress('Error refreshing token:{}'.format(str(e)))
            return action_result.set_status(phantom.APP_ERROR, "'Error refreshing tokens")

    def _handle_create_folder(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        folder_name = param['folder_name']
        root_folder = param['root_folder_id']
        self._authenticate()
        try:
            items = client.folder(folder_id=root_folder).get_items()
            existing_folders = [item.name for item in items]
            if folder_name not in existing_folders:
                subfolder = client.folder(root_folder).create_subfolder(folder_name)
                self.save_progress('Created subfolder with ID {0}'.format(subfolder.id))
                folder = {'created_folder_name':None, 'created_folder_id': None, 'root_folder':None}
                folder['created_folder_name'] = folder_name
                folder['created_folder_id'] = subfolder.id
                folder['root_folder'] = root_folder
                action_result.add_data(folder)
            else:
                self.save_progress('Folder {0} already exists in this location'.format(folder_name))
            return action_result.set_status(phantom.APP_SUCCESS, 'Successfully created folder')
        except Exception as e:
            self.debug_print('BOX error: ', str(e))
            self.save_progress("Client error: {0}".format(str(e)))
            return action_result.set_status(phantom.APP_ERROR, "'Error creating folder")
    def _handle_upload_file(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        vault_ids = ast.literal_eval(param['vault_id'])
        folder_id = param['box_folder_id']
        self._authenticate()
        try:
            items = client.folder(folder_id=folder_id).get_items()
            existing_files = [item.name for item in items]
            count = 0
            for item in vault_ids:
                count += 1
                self.save_progress('File "{0}" out of {1} is uploading'.format(count, len(vault_ids)))
                file_info = Vault.get_file_info(item)
                file_size = file_info[0]['size']
                file_path = file_info[0]['path']
                file_name = file_info[0]['name']
                if file_name not in existing_files:
                    if file_size > 50000000:
                        chunked_uploader = client.folder(folder_id).get_chunked_uploader(file_path)
                        uploaded_file = chunked_uploader.start()
                        updated_file = client.file(uploaded_file.id).update_info({'name': file_name})
                        self.save_progress('File "{0}" uploaded to Box with file ID {1}'.format(updated_file.name, uploaded_file.id))
                    else:
                        new_file = client.folder(folder_id).upload(file_path)
                        updated_file = client.file(new_file.id).update_info({'name': file_name})
                        self.save_progress('File "{0}" uploaded to Box with file ID {1}'.format(updated_file.name, new_file.id))
                else:
                    self.save_progress('File {0} already exists in this location'.format(file_name))
            return action_result.set_status(phantom.APP_SUCCESS, 'Successfully uploaded files')
        except Exception as e:
            self.save_progress("Client error: {0}".format(str(e)))
            return action_result.set_status(phantom.APP_ERROR, "'Error uploading files")

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS
        action_id = self.get_action_identifier()
        self.debug_print("action_id", self.get_action_identifier())
        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)
        elif action_id == 'refresh_token':
            ret_val = self._handle_refresh_token(param)
        elif action_id == 'upload_file':
            ret_val = self._handle_upload_file(param)
        elif action_id == 'create_folder':
            ret_val = self._handle_create_folder(param)
        return ret_val

    def initialize(self):
        self._state = self.load_state()
        config = self.get_config()
        self._base_url = config.get('base_url')
        return phantom.APP_SUCCESS
    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import pudb
    import argparse
    pudb.set_trace()
    argparser = argparse.ArgumentParser()
    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    args = argparser.parse_args()
    session_id = None
    username = args.username
    password = args.password
    if username is not None and password is None:
        import getpass
        password = getpass.getpass("Password: ")
    if username and password:
        try:
            login_url = BoxConnector._get_phantom_base_url() + '/login'
            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']
            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken
            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url
            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)
    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = BoxConnector()
        connector.print_progress_message = True
        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))
    exit(0)
if __name__ == '__main__':
    main()
