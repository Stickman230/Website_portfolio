import pyshark


### BLUETOOTH KEYS READING ######################
#################################################

### AZERTY Keyboard ( painfull :( )

BASE = {
    4:"a", 5:"b", 6:"c", 7:"d", 8:"e", 9:"f",
    10:"g", 11:"h", 12:"i", 13:"j", 14:"k", 15:"l",
    16:"m", 17:"n", 18:"o", 19:"p", 20:"q", 21:"r",
    22:"s", 23:"t", 24:"u", 25:"v", 26:"w", 27:"x",
    28:"y", 29:"z",

    30:"1", 31:"2", 32:"3", 33:"4", 34:"5",
    35:"6", 36:"7", 37:"8", 38:"9", 39:"0",

    40:"\n", 41:"[ESC]", 42:"[BKSP]", 43:"[TAB]", 44:" ",
    45:"-", 46:"+", 47:"{", 48:"}", 49:"|",
    51:":", 52:'"', 53:"~", 54:"<", 55:".", 56:"/",
    57:"[CAPSLOCK]", 79:"[RIGHT]", 80:"[LEFT]", 
    81:"[DOWN]", 82:"[UP]", 100:"\\"
}

SHIFT = {
    4:"A", 5:"B", 6:"C", 7:"D", 8:"E", 9:"F",
    10:"G", 11:"H", 12:"I", 13:"J", 14:"K", 15:"L",
    16:"M", 17:"N", 18:"O", 19:"P", 20:"Q", 21:"R",
    22:"S", 23:"T", 24:"U", 25:"V", 26:"W", 27:"X",
    28:"Y", 29:"Z",

    30:"!", 31:"@", 32:"#", 33:"$", 34:"%",
    35:"^", 36:"&", 37:"*", 38:"(", 39:")",

    40:"\n", 41:"[ESC]", 42:"[BKSP]", 43:"[TAB]", 44:" ",
    45:"-", 46:"+", 47:"{", 48:"}", 49:"|",
    51:":", 52:'"', 53:"~", 54:"<", 55:".", 56:"/",
    57:"[CAPSLOCK]", 79:"[RIGHT]", 80:"[LEFT]", 
    81:"[DOWN]", 82:"[UP]", 100:"\\"
}

IGNORE = {57, 79, 80, 81, 82}  ### caps lock and arrows keys

### Apply our filter to the capture to fetch only what we need before processing using dynamic channel
cap      = pyshark.FileCapture("capture.pcapng", display_filter="btl2cap.cid == 0x0041")
prev     = [0] * 6
output   = []


for pkt in cap:
    try:
        raw  = bytes.fromhex(str(pkt.btl2cap.payload).replace(":", "")) ### Convert payload to bytes
        if raw[0] != 0xa1 or raw[1] != 0x01: continue    ### Ignore packets with wrong HID input report headers
        mod   = raw[2]               ### Fetch modifier
        keys  = list(raw[4:10])      ### Fetch keycodes
        shift = mod in (0x02, 0x20)   ### Check if shift is applied 
        table = SHIFT if shift else BASE
        for k in keys:
            if k==0 or k in IGNORE:  ### ignore arrow keys, caps lock and empty
                continue
            if k not in prev:       ### check that our keys were not pressed before
                token = table.get(k, f"[{k}]")
                
                if token == "[BKSP]":  ### Apply the backspaces for a cleaner read of output
                    if output:
                        output.pop()
                else:
                    output.append(token)
        prev = keys
    except: 
        pass

print("".join(output))

### OFFLINE DECRIPTION OF PAYLOAD ##############
#################################################

from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

salt_hex = "OhlalaTeteDeSaMerePtn"
pepper_hex = "NoooonTapePasContreLeMurGroooos"
iv_prefix_hex = "a7a70ee4939113"

payload = bytes.fromhex(
    "a7a70ee49391130000000000"
    "a42f44d4b0af500a1648c65a29073624e6a4be7cb82ae1d1"
    "197f240a7195ef64dc8a9ec86e31241ddf4eff8a94a489d7"
    "3c231684ff6f230e0bf83486"
)

nonce = payload[:12]
ciphertext = payload[12:]

key_material = (salt_hex + pepper_hex + iv_prefix_hex).encode()
key = sha256(key_material).digest()

plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
print("FLAG IS:", plaintext.decode())