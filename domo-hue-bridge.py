#!/usr/bin/env python3

#
# https://github.com/msp9174/domotiga-hue-bridge
# Released under MIT license - Copyright 2018 - Mark Parker
#

import requests
import flask
import json
import threading
import socket
import socketserver
import time
import json
import datetime
import re
import sys
import zlib

def getIpAddress():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

# Config
DOMOTIGA_BASE_URL = "http://localhost:9090"
LISTEN_IP = getIpAddress()
HTTP_LISTEN_PORT = 8000
ECHO_GROUP = "Alexa"

#
# Domotiga
#
class Domotiga:
    entities = {}
    headers = {}

    def __init__(self, base_url=DOMOTIGA_BASE_URL):
        self.base_url = base_url
        self.headers = { 'content-type': 'application/json' }
        self.fetch_entities()

    def fetch_entities(self):
        print("Fetching Domotiga entities...")

        entities = {}

        data = {"jsonrpc": "2.0", "method": "device.list", "params": {"groups" : [ECHO_GROUP]}, "id": 1}
        req = requests.post("{0}/".format(self.base_url), headers=self.headers, json=data)
        devices_json = json.loads(req.text)

        entries = 0

        for device in devices_json['result']:
            #Enumerate devices list and call device.get to get all details, specifically group info.
            print ("Getting info for " + device['name'])

            device_data = {"jsonrpc": "2.0", "method": "device.get", "params": {"device_id" : device['device_id']}, "id": 1}
            req = requests.post("{0}".format(self.base_url), headers=self.headers, json=device_data)

            device_json = json.loads(req.text)

            if ECHO_GROUP in device_json['result']['groups']:
 
                # API limit in Echo implementation
                entries += 1
                if entries > 49:
                    print("FATAL ERROR: Echo only supports up to 49 devices per Hue hub via local API")
                    sys.exit(1)
                           
                
                domain_type = 'light'
                new_entity_name = device_json['result']['name']

                #Get device status
                device_status = False
                
                for values in device_json['result']['values']:
                    if ('valuenum' in values) and (values['valuenum'] == 1):
                        if ('value' in values) and (values['value'] == 'On'):
                            device_status = True

                # Filter the friendly entity name so that it only contains letters and spaces
                new_entity_name = re.sub("[^\w\ ]+", "", new_entity_name, re.U)

                # Give device unique ID
                unique_id = zlib.crc32(("DOM" + str(device_json['result']['device_id'])).encode('utf-8'))

                self.entities[unique_id] = {}
                self.entities[unique_id]['name'] = new_entity_name
                self.entities[unique_id]['entity_id'] = device_json['result']['device_id']
                self.entities[unique_id]['domain_type'] = domain_type
                self.entities[unique_id]['cached_on'] = device_status
                self.entities[unique_id]['cached_bri'] = 0

                print('Adding {0}: device_id "{1}" with spoken name "{2}"'.format(unique_id, device_json['result']['device_id'], new_entity_name))

        # Did we find any eligible entities?
        if len(self.entities) == 0:
            print("ERROR: No eligible devices found. Did you configure Domotiga?")
            sys.exit(1)

        print("Using {0} devices from Domotiga\n".format(len(self.entities)))

    def turn_on(self, entity_id):
        print('Asking Domotiga to turn ON entity "{0}"'.format(entity_id))

        device_on = {"jsonrpc": "2.0", "method": "device.set", "params": {"device_id" : entity_id, "valuenum" : 1, "value": "On"}, "id": 1}
        req = requests.post("{0}".format(self.base_url), headers=self.headers, json=device_on)

        if req.status_code != 200:
            print("Call to Domotiga failed: {0}".format(req.json()))
            flask.abort(500)

    def turn_off(self, entity_id):
        print('Asking Domotiga to turn OFF entity "{0}"'.format(entity_id))

        device_off = {"jsonrpc": "2.0", "method": "device.set", "params": {"device_id" : entity_id, "valuenum" : 1, "value": "Off"}, "id": 1}
        req = requests.post("{0}".format(self.base_url), headers=self.headers, json=device_off)

        if req.status_code != 200:
            print("Call to Domotiga failed: {0}".format(req.json()))
            flask.abort(500)

    def turn_brightness(self, entity_id, brightness):
        print('Asking Domotiga to turn ON entity "{0}" and set brightness to {1}'.format(entity_id, brightness))

    def get_status(self, unique_id):
        print('Asking Domotiga for status of {0}'.format(self.entities[unique_id]['name']))

        device_data = {"jsonrpc": "2.0", "method": "device.get", "params": {"device_id" : self.entities[unique_id]['entity_id']}, "id": 1}
        req = requests.post("{0}".format(self.base_url), headers=self.headers, json=device_data)
        device_json = json.loads(req.text)

        #Get device status
        device_status = False
                
        for values in device_json['result']['values']:
            if ('valuenum' in values) and (values['valuenum'] == 1):
                if ('value' in values) and (values['value'] == 'On'):
                    device_status = True

        self.entities[unique_id]['cached_on'] = device_status

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

""".format(LISTEN_IP, HTTP_LISTEN_PORT).replace("\n", "\r\n").encode('utf-8')

    stop_thread = False

    def run(self):

        # Listen for UDP port 1900 packets sent to SSDP multicast address
        print("UPNP Responder Thread started...")
        ssdpmc_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Required for receiving multicast
        ssdpmc_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ssdpmc_socket.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(LISTEN_IP))
        ssdpmc_socket.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton("239.255.255.250") + socket.inet_aton(LISTEN_IP))

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
                print("UPNP Responder sending response to {0}:{1}".format(addr[0], addr[1]))
                ssdpout_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                ssdpout_socket.sendto(self.UPNP_RESPONSE, addr)
                ssdpout_socket.close()

    def stop(self):
        # Request for thread to stop
        self.stop_thread = True

# Global Variables
dm = Domotiga()
upnp_responder = UPNPResponderThread()
app = flask.Flask(__name__)

#
# Flask Webserver Routes
#

#
# /description.xml required as part of Hue hub discovery
#
DESCRIPTION_XML_RESPONSE = """<?xml version="1.0" encoding="UTF-8" ?>
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
<presentationURL>index.html</presentationURL>
<iconList>
<icon>
<mimetype>image/png</mimetype>
<height>48</height>
<width>48</width>
<depth>24</depth>
<url>hue_logo_0.png</url>
</icon>
<icon>
<mimetype>image/png</mimetype>
<height>120</height>
<width>120</width>
<depth>24</depth>
<url>hue_logo_3.png</url>
</icon>
</iconList>
</device>
</root>
""".format(LISTEN_IP, HTTP_LISTEN_PORT)

@app.route('/description.xml', strict_slashes=False, methods = ['GET'])
def hue_description_xml():
    return flask.Response(DESCRIPTION_XML_RESPONSE, mimetype='text/xml')

#
# Device enumeration request from Echo
#
@app.route('/api/<token>/lights', strict_slashes=False, methods = ['GET'])
@app.route('/api/<token>/lights/', strict_slashes=False, methods = ['GET'])
def hue_api_lights(token):
    dm.fetch_entities()
    json_response = {}

    for id_num in dm.entities.keys():
        json_response[id_num] = {'state': {'on': dm.entities[id_num]['cached_on'], 'bri': dm.entities[id_num]['cached_bri'], 'hue':0, 'sat':0, 'effect': 'none', 'ct': 0, 'alert': 'none', 'reachable':True}, 'type': 'Dimmable light', 'name': dm.entities[id_num]['name'], 'modelid': 'LWB004', 'manufacturername': 'Philips', 'uniqueid': id_num, 'swversion': '66012040'}

    return flask.Response(json.dumps(json_response), mimetype='application/json')

#
# Change state request from Echo
#
@app.route('/api/<token>/lights/<int:id_num>/state', methods = ['PUT'])
def hue_api_put_light(token, id_num):
    request_json = flask.request.get_json(force=True)
    print("Echo PUT {0}/state: {1}".format(id_num, request_json))

    # Echo requested device be turned "on"
    if 'on' in request_json and request_json['on'] == True:
        dm.turn_on(dm.entities[id_num]['entity_id'])
        dm.entities[id_num]['cached_on'] = True
        return flask.Response(json.dumps([{'success': {'/lights/{0}/state/on'.format(id_num): True }}]), mimetype='application/json', status=200)

    # Scripts and scenes can't really be turned off so treat 'off' as 'on'
    if 'on' in request_json and request_json['on'] == False and dm.entities[id_num]['domain_type'] in ['script', 'scene']:
        dm.turn_on(dm.entities[id_num]['entity_id'])
        dm.entities[id_num]['cached_on'] = False
        return flask.Response(json.dumps([{'success': {'/lights/{0}/state/on'.format(id_num): True }}]), mimetype='application/json', status=200)

    # Echo requested device be turned "off"
    if 'on' in request_json and request_json['on'] == False:
        dm.turn_off(dm.entities[id_num]['entity_id'])
        dm.entities[id_num]['cached_on'] = False
        return flask.Response(json.dumps([{'success': {'/lights/{0}/state/on'.format(id_num): False }}]), mimetype='application/json', status=200)

    # Echo requested a change to brightness
    if 'bri' in request_json:
        dm.turn_brightness(dm.entities[id_num]['entity_id'], request_json['bri'])
        dm.entities[id_num]['cached_bri'] = request_json['bri']
        return flask.Response(json.dumps([{'success': {'/lights/{0}/state/bri': request_json['bri']}}]), mimetype='application/json', status=200)

    print("Unhandled API request: {0}".format(request_json))
    flask.abort(500)

#
# Echo pulls individual device state to make sure command went through
#
@app.route('/api/<token>/lights/<int:id_num>', strict_slashes=False, methods = ['GET'])
def hue_api_individual_light(token, id_num):
    dm.get_status(id_num)
    json_response = {}


    json_response = {'state': {'on': dm.entities[id_num]['cached_on'], 'bri': dm.entities[id_num]['cached_bri'], 'hue':0, 'sat':0, 'effect': 'none', 'ct': 0, 'alert': 'none', 'reachable':True}, 'type': 'Dimmable light', 'name': dm.entities[id_num]['name'], 'modelid': 'LWB004', 'manufacturername': 'Philips', 'uniqueid': id_num, 'swversion': '66012040'}

    return flask.Response(json.dumps(json_response), mimetype='application/json')

#
# Catch error state
#
@app.route('/api/<token>/groups', strict_slashes=False)
@app.route('/api/<token>/groups/0', strict_slashes=False)
def hue_api_groups_0(token):
    print("ERROR: If echo requests /api/groups that usually means it failed to parse /api/lights.")
    print("This probably means the Echo didn't like something in a name.")
    return flask.abort(500)

#
# Assign a dummy username to Echo if it asks for one
#
@app.route('/api', strict_slashes=False, methods = ['POST'])
def hue_api_create_user():
    request_json = flask.request.get_json(force=True)

    if 'devicetype' not in request_json:
        return flask.abort(500)

    print("Echo asked to be assigned a username")
    return flask.Response(json.dumps([{'success': {'username': '12345678901234567890'}}]), mimetype='application/json')


#
# Startit all up...
#
def main():
    global upnp_responder
    global app

    upnp_responder.start()

    print("Starting Flask for HTTP listening on {0}:{1}...".format(LISTEN_IP, HTTP_LISTEN_PORT))
    app.run(host=LISTEN_IP, port=HTTP_LISTEN_PORT, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
