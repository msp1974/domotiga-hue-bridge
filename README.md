# domotiga-hue-bridge

This is a python script that integrates Domotiga devices with Amazon Echo/Alexa using a Hue Emulator.  At the moment it only supports lights and does not support brightness settings.  However, any device you want to switch on or off in Domotiga from your Echo can be done through this script.

**Note:**

I created this script as I have a number of lamps that use wifi sockets and previously used fauxmo to integrate with my Echos.  However, if you want to use Alexa groups and be able to say 'Alexa turn the lights on' and she turns the lights on in the room your echo device is in, then they need to be seen by your Echo as lights.  This works really well with this script but you need to create groups in the Alexa app and pair your Echo devices with the Domotiga devices that will show in their after discovery.

# How to Use

First, you need to create a group in Domotiga that each device you want to make available to your Echo belongs to.  I used a group named 'Alexa' but you can choose your own.

In the script near the top is a config section.

`# Config
DOMOTIGA_BASE_URL = "http://localhost:9090"
LISTEN_IP = getIpAddress()
HTTP_LISTEN_PORT = 8000
ECHO_GROUP = "Alexa"`

Set the DOMOTIGA_BASE_URL to be the url of the JSONRPC server on Domotiga.  If you are running this on the same server as the Domotiga server, then this is probably already set correctly.

The HTTP_LISTEN_PORT is the port the Hue Emulator responds on.  You can set this to anything that is not already in use by another process.

Set the ECHO_GROUP to be the name of the Domotiga group you created earlier and have added to the devices you want to be controlled by your Echo.

That's it!  Run this script and get your Echo to do a device discovery.  Your Domotiga devices should now show in the Alexa app.
