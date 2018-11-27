#!/usr/bin/env python3

#
# https://github.com/msp9174/domotiga-hue-bridge
# Released under MIT license - Copyright 2018 - Mark Parker
#

import requests
import flask
import json
import time
import json
import datetime
import re
import sys
import zlib
import threading
import socket
import socketserver
import logging
import argparse
import config
import math
from werkzeug.contrib.fixers import ProxyFix

global upnp_responder
global app


def getIpAddress():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

SERVER_IP = getIpAddress()

if config.PROXY:
    LISTEN_IP = '127.0.0.1'
else:
    LISTEN_IP = SERVER_IP


#Set Logging Level
parser = argparse.ArgumentParser("domo-hue-bridge")
parser.add_argument("--debug", help="Set debugging to a file for diagnosis of discovery issues", action="store_true")
args = parser.parse_args()
if args.debug:
    print("Running in DEBUG Mode")
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)-5.5s]  %(message)s",
        filemode='w',
        handlers=[
            logging.FileHandler("domo-hue-bridge.log", mode = 'w'),
            logging.StreamHandler()
        ])
else:
    print("Running in NORMAL Mode")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(message)s",
        handlers=[
            logging.StreamHandler()
        ])
#
# Domotiga
#
class Domotiga:
    entities = {}
    headers = {}

    def __init__(self, base_url=config.DOMOTIGA_BASE_URL):
        self.base_url = base_url
        self.headers = { 'content-type': 'application/json' }
        self.fetch_entities()

    def convert_to_dim_value(self, brightness): 
        dim_value = ""
        dim_value = "Dim " + str(int(round((int(brightness)/254)*100)))                                           
        return dim_value

    def convert_from_dim_value(self, device_bri):
        dim_value = 0
        dim_value = int(device_bri.replace("Dim","").strip())
        dim_value = int(math.ceil((int(dim_value)/100) * 254))
        return dim_value

    def fetch_entities(self):
        logging.info("Fetching Domotiga entities...")

        entities = {}

        data = {"jsonrpc": "2.0", "method": "device.list", "params": {"groups" : [config.ECHO_GROUP]}, "id": 1}
        req = requests.post("{0}/".format(self.base_url), headers=self.headers, json=data)
        devices_json = json.loads(req.text)

        entries = 0

        for device in devices_json['result']:
            #Enumerate devices list and call device.get to get all details, specifically group info.
            logging.info("Getting info for " + device['name'])

            device_data = {"jsonrpc": "2.0", "method": "device.get", "params": {"device_id" : device['device_id']}, "id": 1}
            req = requests.post("{0}".format(self.base_url), headers=self.headers, json=device_data)

            device_json = json.loads(req.text)

            if config.ECHO_GROUP in device_json['result']['groups']:
 
                # API limit in Echo implementation
                entries += 1
                if entries > 49:
                    logging.warn("FATAL ERROR: Echo only supports up to 49 devices per Hue hub via local API")
                    sys.exit(1)
                           
                
                domain_type = 'light'
                new_entity_name = device_json['result']['name']

                #Get device type
                device_type = "Colour"
                
                if device_json['result']['switchable'] == -1:
                    device_type = "Switchable"

                if device_json['result']['dimable'] == -1:
                    device_type = "Dimable"



                #Get device status
                device_status = False

                #Get device brightness
                device_bri = 1
                
                for values in device_json['result']['values']:
                    if ('valuenum' in values) and (values['valuenum'] == 1):
                        if ('value' in values) and (values['value'] == 'On'):
                            device_status = True
                            device_bri = 254

                        if ('value' in values) and ('Dim' in values['value']):
                            device_bri = self.convert_from_dim_value(values['value'])

                            if device_bri > 0:
                                device_status = True
                    
                # Filter the friendly entity name so that it only contains letters and spaces
                new_entity_name = re.sub("[^\w\ ]+", "", new_entity_name, re.U)

                # Give device unique ID
                unique_id = zlib.crc32(("DOM" + str(device_json['result']['device_id'])).encode('utf-8'))

                self.entities[unique_id] = {}
                self.entities[unique_id]['name'] = new_entity_name
                self.entities[unique_id]['entity_id'] = device_json['result']['device_id']
                self.entities[unique_id]['domain_type'] = domain_type
                self.entities[unique_id]['device_type'] = device_type
                self.entities[unique_id]['cached_on'] = device_status
                self.entities[unique_id]['cached_bri'] = device_bri

                logging.info('Adding {0}: device_id "{1}" with spoken name "{2}"'.format(unique_id, device_json['result']['device_id'], new_entity_name))

        # Did we find any eligible entities?
        if len(self.entities) == 0:
            logging.warn("ERROR: No eligible devices found. Did you configure Domotiga?")
            sys.exit(1)

        logging.info("Using {0} devices from Domotiga\n".format(len(self.entities)))


    def turn_on(self, unique_id):
        logging.info('Asking Domotiga to turn ON entity "{0}"'.format(self.entities[unique_id]['name']))

        device_on = {"jsonrpc": "2.0", "method": "device.set", "params": {"device_id" : self.entities[unique_id]['entity_id'], "valuenum" : 1, "value": "On"}, "id": 1}

        req = requests.post("{0}".format(self.base_url), headers=self.headers, json=device_on)

        if req.status_code != 200:
            logging.warn("Call to Domotiga failed: {0}".format(req.json()))
            flask.abort(500)

    def turn_off(self, unique_id):
        logging.info('Asking Domotiga to turn OFF entity "{0}"'.format(self.entities[unique_id]['name']))

        device_off = {"jsonrpc": "2.0", "method": "device.set", "params": {"device_id" : self.entities[unique_id]['entity_id'], "valuenum" : 1, "value": "Off"}, "id": 1}
        req = requests.post("{0}".format(self.base_url), headers=self.headers, json=device_off)

        if req.status_code != 200:
            logging.warn("Call to Domotiga failed: {0}".format(req.json()))
            flask.abort(500)

    def turn_brightness(self, unique_id, brightness):
        logging.info('Asking Domotiga to turn ON entity "{0}" and set brightness to {1}'.format(self.entities[unique_id]['name'], brightness))

        device_bri = {"jsonrpc": "2.0", "method": "device.set", "params": {"device_id" : self.entities[unique_id]['entity_id'], "valuenum" : 1, "value": self.convert_to_dim_value(brightness)}, "id": 1}
        logging.debug(device_bri)
        req = requests.post("{0}".format(self.base_url), headers=self.headers, json=device_bri)
        logging.debug(req.json())

        if req.status_code != 200:
            logging.warn("Call to Domotiga failed: {0}".format(req.json()))
            flask.abort(500)

    def get_status(self, unique_id):
        logging.info('Asking Domotiga for status of {0}'.format(self.entities[unique_id]['name']))

        device_data = {"jsonrpc": "2.0", "method": "device.get", "params": {"device_id" : self.entities[unique_id]['entity_id']}, "id": 1}
        req = requests.post("{0}".format(self.base_url), headers=self.headers, json=device_data)

        if req.status_code != 200:
            logging.warn("Call to Domotiga failed: {0}".format(req.json()))
            flask.abort(500)
            
        device_json = json.loads(req.text)

        #Get device status
        device_status = False

        #Get device brightness
        device_bri = 1
                
        for values in device_json['result']['values']:
            if ('valuenum' in values) and (values['valuenum'] == 1):
                if ('value' in values) and (values['value'] == 'On'):
                    device_status = True
                    device_bri = 254

                if ('value' in values) and ('Dim' in values['value']):
                    device_bri = self.convert_from_dim_value(values['value'])

                    if device_bri > 0:
                        device_status = True

        self.entities[unique_id]['cached_on'] = device_status
        self.entities[unique_id]['cached_bri'] = device_bri
                                                             

    def get_device_json(self, unique_id):
        device_json = {}
        if self.entities[unique_id]['device_type'] == "Switchable":
            device_json = {'state': {'on': self.entities[unique_id]['cached_on'], 'alert': 'none', 'reachable':True}, 'type': 'Non Dimmable light', 'name': self.entities[unique_id]['name'], 'modelid': 'LWB004', 'manufacturername': 'Philips', 'uniqueid': unique_id, 'swversion': '66012040'}

        elif self.entities[unique_id]['device_type'] == "Dimable":
            device_json = {'state': {'on': self.entities[unique_id]['cached_on'], 'bri': self.entities[unique_id]['cached_bri'], 'alert': 'none', 'reachable':True}, 'type': 'Dimmable light', 'name': self.entities[unique_id]['name'], 'modelid': 'LWB010', 'manufacturername': 'Philips', 'uniqueid': unique_id, 'swversion': '1.15.0_r18729'}

        elif self.entities[unique_id]['device_type'] == "Colour":
            device_json = {'state': {'on': self.entities[unique_id]['cached_on'], 'bri': self.entities[unique_id]['cached_bri'], 'hue':0, 'sat':0, 'effect': 'none', 'ct': 0, 'alert': 'none', 'reachable':True}, 'type': 'Extended color light', 'name': self.entities[unique_id]['name'], 'modelid': 'LCT015', 'manufacturername': 'Philips', 'uniqueid': unique_id, 'swversion': '1.29.0_r21169'}

        else:
            device_json = {}

        return device_json

    def debug_device(self, device_id):

        device_data = {"jsonrpc": "2.0", "method": "device.get", "params": {"device_id" : device_id}, "id": 1}
        req = requests.post("{0}".format(self.base_url), headers=self.headers, json=device_data)

        return req.text



#
# UPNP Responder Thread Object
#
class UPNPResponderThread(threading.Thread):

    UPNP_RESPONSE = """HTTP/1.1 200 OK
CACHE-CONTROL: max-age=60
EXT:
LOCATION: http://{0}:{1}/description.xml
SERVER: FreeRTOS/6.0.5, UPnP/1.0, IpBridge/0.1
ST: urn:schemas-upnp-org:device:basic:1
USN: uuid:Socket-1_0-221438K0100073::urn:schemas-upnp-org:device:basic:1

""".format(SERVER_IP, config.PROXY_PORT if config.PROXY else config.HTTP_LISTEN_PORT).replace("\n", "\r\n").encode('utf-8')

    stop_thread = False

    def run(self):

        # Listen for UDP port 1900 packets sent to SSDP multicast address
        logging.info("UPNP Responder Thread started...")
        ssdpmc_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Required for receiving multicast
        ssdpmc_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ssdpmc_socket.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(LISTEN_IP))
        ssdpmc_socket.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton("239.255.255.250") + socket.inet_aton(SERVER_IP))

        ssdpmc_socket.bind(("239.255.255.250", 1900))

        while True:
            try:
                data, addr = ssdpmc_socket.recvfrom(1024)
            except socket.error as e:
                if stop_thread == True:
                    print("UPNP Reponder Thread closing socket and shutting down...")
                    ssdpmc_socket.close()
                    return
                print ("UPNP Responder socket.error exception occured: {0}".format(e.__str__))

            # SSDP M-SEARCH method received - respond to it unicast with our info
            if "M-SEARCH" in data.decode('utf-8'):
                #logging.debug("-----------------------------------------------------------------------------")
                logging.debug("UPNP Request Received from {0}:{1} \r\n".format(addr[0], addr[1]))
                #logging.debug("-----------------------------------------------------------------------------")
                logging.info("UPNP Responder sending response to {0}:{1}".format(addr[0], addr[1]))
                ssdpout_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                ssdpout_socket.sendto(self.UPNP_RESPONSE, addr)
                ssdpout_socket.close()
                #logging.debug("-----------------------------------------------------------------------------")
                #logging.debug("UPNP Response \r\n" + self.UPNP_RESPONSE.decode('utf-8'))
                #logging.debug("-----------------------------------------------------------------------------")

    def stop(self):
        # Request for thread to stop
        self.stop_thread = True



# Global Variables
dm = Domotiga()
upnp_responder = UPNPResponderThread()
app = flask.Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)

#Start UPNP Server
upnp_responder.start()


#
# Flask Webserver Routes
#

#
# /description.xml required as part of Hue hub discovery
#
DESCRIPTION_XML_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
<specVersion>
<major>1</major>
<minor>0</minor>
</specVersion>
<URLBase>http://{0}:{1}/</URLBase>
<device>
<deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
<friendlyName>Domotiga-Echo ({0})</friendlyName>
<manufacturer>Royal Philips Electronics</manufacturer>
<manufacturerURL>http://www.philips.com</manufacturerURL>
<modelDescription>Philips hue Personal Wireless Lighting</modelDescription>
<modelName>Philips hue bridge 2015</modelName>
<modelNumber>BSB002</modelNumber>
<modelURL>http://www.meethue.com</modelURL>
<serialNumber>1234</serialNumber>
<UDN>uuid:2f402f80-da50-11e1-9b23-001788255acc</UDN>
</device>
</root>
""".format(SERVER_IP, config.PROXY_PORT if config.PROXY else config.HTTP_LISTEN_PORT)


@app.route('/api/<token>/lights/<int:id_num>/debug', methods = ['GET'])
def debug_device(token, id_num):
    r = dm.debug_device(id_num)
    logging.debug(r)
    return flask.Response(r)


@app.route('/description.xml', strict_slashes=False, methods = ['GET'])
def hue_description_xml():
    r = DESCRIPTION_XML_RESPONSE
    logging.debug("ECHO GET description.xml from " + flask.request.remote_addr)
    #logging.debug(r)
    return flask.Response(r, mimetype='text/xml')

#
# Device enumeration request from Echo
#
@app.route('/api/<token>/lights', strict_slashes=False, methods = ['GET'])
@app.route('/api/<token>/lights/', strict_slashes=False, methods = ['GET'])
def hue_api_lights(token):
    logging.info("Echo GET Device Enumeration from {0}".format(flask.request.remote_addr))
    dm.fetch_entities()
    json_response = {}

    for id_num in dm.entities.keys():
        json_response[id_num] = dm.get_device_json(id_num)

    r = json.dumps(json_response)
    logging.debug("Enumeration Response")
    logging.debug(r)
    return flask.Response(r, mimetype='application/json')

#
# Change state request from Echo
#
@app.route('/api/<token>/lights/<int:id_num>/state', methods = ['PUT'])
def hue_api_put_light(token, id_num):
    request_json = flask.request.get_json(force=True)
    logging.info("Echo PUT {0} - {1}/state: {2} from {3}".format(id_num, dm.entities[id_num]['name'], request_json, flask.request.remote_addr))

    # Echo requested a change to brightness
    if 'bri' in request_json and 'on' in request_json:
        dm.turn_brightness(id_num, request_json['bri'])
        dm.entities[id_num]['cached_bri'] = request_json['bri']

        r = json.dumps([{'success': {'/lights/{0}/state/on'.format(id_num): request_json['on']}},{'success': {'/lights/{0}/state/bri'.format(id_num): request_json['bri']}}])
        logging.debug("State Response")
        logging.debug(r)
        return flask.Response(r, mimetype='application/json', status=200)

    # Echo requested device be turned "on"
    if 'on' in request_json and request_json['on'] == True:
        dm.turn_on(id_num)
        dm.entities[id_num]['cached_on'] = True

        r = json.dumps([{'success': {'/lights/{0}/state/on'.format(id_num): True }}])
        logging.debug("State Response")
        logging.debug(r)
        return flask.Response(r, mimetype='application/json', status=200)

    # Scripts and scenes can't really be turned off so treat 'off' as 'on'
    if 'on' in request_json and request_json['on'] == False and dm.entities[id_num]['domain_type'] in ['script', 'scene']:
        dm.turn_on(id_num)
        dm.entities[id_num]['cached_on'] = False

        r= json.dumps([{'success': {'/lights/{0}/state/on'.format(id_num): True }}])
        logging.debug("State Response")
        logging.debug(r)
        return flask.Response(r, mimetype='application/json', status=200)

    # Echo requested device be turned "off"
    if 'on' in request_json and request_json['on'] == False:
        dm.turn_off(id_num)
        dm.entities[id_num]['cached_on'] = False

        r=json.dumps([{'success': {'/lights/{0}/state/on'.format(id_num): False }}])
        logging.debug("State Response")
        logging.debug(r)
        return flask.Response(r, mimetype='application/json', status=200)

    # Echo requested a change to brightness
    if 'bri' in request_json:
        dm.turn_brightness(id_num, request_json['bri'])
        dm.entities[id_num]['cached_bri'] = request_json['bri']

        r= json.dumps([{'success': {'/lights/{0}/state/bri'.format(id_num): request_json['bri']}}])
        logging.debug("State Response")
        logging.debug(r)
        return flask.Response(r, mimetype='application/json', status=200)

    logging.warn("Unhandled API request: {0}".format(request_json))
    flask.abort(500)

#
# Echo pulls individual device state to make sure command went through
#
@app.route('/api/<token>/lights/<int:id_num>', strict_slashes=False, methods = ['GET'])
def hue_api_individual_light(token, id_num):
    logging.info("Echo GET {0} - {1} status request from {2}".format(id_num, dm.entities[id_num]['name'], flask.request.remote_addr))
    dm.get_status(id_num)
    json_response = {}


    json_response = dm.get_device_json(id_num)

    r = json.dumps(json_response)
    logging.debug("Response to status request \r\n" + r)

    return flask.Response(r, mimetype='application/json')

#
# Catch error state
#
@app.route('/api/<token>/groups', strict_slashes=False)
@app.route('/api/<token>/groups/0', strict_slashes=False)
def hue_api_groups_0(token):
    logging.info("ERROR: If echo requests /api/groups that usually means it failed to parse /api/lights.")
    logging.info("This probably means the Echo didn't like something in a name.")
    return flask.abort(500)

#
# Assign a dummy username to Echo if it asks for one
#
@app.route('/api', strict_slashes=False, methods = ['POST'])
def hue_api_create_user():
    request_json = flask.request.get_json(force=True)

    if 'devicetype' not in request_json:
        return flask.abort(500)

    logging.info("Echo asked to be assigned a username")
    return flask.Response(json.dumps([{'success': {'username': '62017234447039242381'}}]), mimetype='application/json')


#
# Start it all up...
#
if __name__ == "__main__":

    logging.info("Starting Flask for HTTP listening on {0}:{1}...".format(LISTEN_IP, config.HTTP_LISTEN_PORT))
    app.run(host=LISTEN_IP, port=config.HTTP_LISTEN_PORT, threaded=True, use_reloader=False, debug=False)
