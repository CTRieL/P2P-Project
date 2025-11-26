import os

CONFIG = {
    "PEER_DISCOVERY_PORT" : 5050,
    "MESSAGE_PORT" : 6060,
    
    #RSA 
    "RSA_KEY_FOLDER" : "keys",
    "RSA_KEY_SIZE" : 2048,
    
    #AES
    "AES_KEY_SIZE" : 32,
    "AES_MODE" : "GCM",
    
    #Hybrid encryption
    "USE_HYBRID" : True,
    
    #network
    "DISCOVERY_BROADCAST_ADDR" : "<broadcast>",
    "DISCOVERY_INTERVAL" : 5,
    
    #debug
    "DEBUG" : True
}

def get(key):
    return CONFIG.get(key)