#Domotiga Config
DOMOTIGA_BASE_URL = "http://localhost:9090"
ECHO_GROUP = "Alexa"

#Hue Bridge Config
HTTP_LISTEN_PORT = 8000		# Port the Hue Bridge will run on
PROXY = True                    # Set to true whe running via proxy, false when standalone
PROXY_PORT = 80                 # If running via proxy. What port the proxy is running on







#Configuring via a Proxy
#When running via proxy:

#   set the HTTP_LISTEN_PORT to 8000 or some available port
#   set IP_MODE to local so that it can only be accessed via the proxy
#   Set proxy port to 80 - or whatever port proxy is running on

