# domotiga-hue-bridge

This is a python script that integrates Domotiga devices with Amazon Echo/Alexa using a Hue Emulator.  This now supports both on/off and dimable lights.  See below for how to configure between on/off and dimable lights in Domotiga.  It requires Python 3.4 or above.

**Note:**

I created this script as I have a number of lamps that use wifi sockets and previously used fauxmo to integrate with my Echos.  However, if you want to use Alexa groups and be able to say 'Alexa turn the lights on' and she turns the lights on in the room your echo device is in, then they need to be seen by your Echo as lights.  This works really well with this script but you need to create groups in the Alexa app and pair your Echo devices with the Domotiga devices that will show in their after discovery.

# How to Use

First, you need to create a group in Domotiga that each device you want to make available to your Echo belongs to.  I used a group named 'Alexa' but you can choose your own.

For each device in Domotiga you want to expose to Alexa, set 'Device can be switched' for on/off lights and 'Device can be dimmed or has a setpoint' for dimable lights in the devices options.

NOTE: If you change these on a device then you will need to delete the device from Alexa and re discover to reflect the change.

In config.py is where you set the config parameters.

```
DOMOTIGA_BASE_URL = "http://localhost:9090"
ECHO_GROUP = "Alexa"

HTTP_LISTEN_PORT = 8000
PROXY = False
PROXY_PORT = 80

```

Set the DOMOTIGA_BASE_URL to be the url of the JSONRPC server on Domotiga.  If you are running this on the same server as the Domotiga server, then this is probably already set correctly.

Set the ECHO_GROUP to be the name of the Domotiga group you created earlier and have added to the devices you want to be controlled by your Echo.

The HTTP_LISTEN_PORT is the port the Hue Emulator responds on.  You can set this to anything that is not already in use by another process.

# Amazon Echo v2, Dot v3 and Google Home

Newer Amazon Alexa devices and Google home seem to need to have the domo-hue-bridge running on port 80 and will not discover devices if domo-hue-bridge is running on any other port.

There are 2 options to make this work with newer devices.

1) Run domo-hue-bridge on port 80 by setting HTTP_LISTEN_PORT = 80
2) Run domo-hue-bridge behind an Apache, Lighttpd or other webserver proxy.  This allows you to alos run other web applications on the same linux box on port 80.

# Configuring domo-hue-bridge behind a proxy

Fisrtly set the HTTP_LISTEN_PORT to 8000 (or something that is free on your server)

Set PROXY = True.  This will make domo-hue-bridge run on localhost only so that it does not expose to your network.
Set PROXY_PORT to the port your proxy is running on.  In order to use this for newer Echo devices this must be port 80.

Configure your webserver to proxy /description.xml and /api to forward to localhost:8000 (or what ever port you have set HTTP_LISTEN_PORT to).

Below is the configuration for an Apache server proxy.

```
ProxyPreserveHost On

ProxyPass /api http://127.0.0.1:8000/api
ProxyPassReverse /api https://127.0.0.1:8000/api

ProxyPass /description.xml http://127.0.0.1:8000/description.xml
ProxyPassReverse /description.xml http://127.0.0.1:8000/description.xml
```

That's it!  Run this script and get your Echo to do a device discovery.  Your Domotiga devices should now show in the Alexa app.

# Installing domo-hue-bridge as a service

I have included a sample systemd script to be able to install domo-hue-bridge as a service.
If you are not sure how to do this, there are plenty of how-to's available on the web.

# Debug Mode

To help identify issues with device discovery or control, domo-hue-bridge has a debug mode which will print out detail of the messages back and forth from Alexa.  Run in debug mode from the command line with the --debug flag.  Ie python3 domo-hue-bridge.py --debug

# Credits

domo-hue-bridge is based on the fabulous ha-local-echo script by Bruce Locke which has been amended to use the Domotiga JsonRPC Rest API instead of home-assistant.
