#! /usr/bin/env python3

__author__ = "Berry van Halderen"
__date__ = "$$"

import os
import sys
import getopt
import yaml
import re
import pkcs11
import base64
import binascii
import xml.dom.minidom

''''
Limitations:
- Only one PKCS#11 token for exporting public keys supported at any one time
- Hardware PKCS#11 token should be specified as first repository,  SoftHSM based
  token as second repository.
- Only migrates RSA public keys
- Token PIN must be specified in the configuration file
'''

tokenmodule   = "/usr/local/lib/softhsm/libsofthsm2.so"
tokenlabel    = "SoftHSM"
tokenpin      = "1234"
signconffname = None

def main():
    try:
        if sys.argv[1] == "export":
            readconf(sys.argv[2], sys.argv[3], 0)
            lib = pkcs11.lib(tokenmodule)
            token = lib.get_token(token_label=tokenlabel)
            session = token.open(user_pin=tokenpin, rw=False)
            ( signconf, keys ) = readsignconf(signconffname)
            exportkeys(session, keys)
            session.close()
            patchsignconf(signconf, keys)
            writesignconf(signconf, signconffname, "pseudo")
        elif sys.argv[1] == "import":
            readconf(sys.argv[2], sys.argv[3], 1)
            lib = pkcs11.lib(tokenmodule)
            token = lib.get_token(token_label=tokenlabel)
            session = token.open(user_pin=tokenpin, rw=True)
            ( signconf, keys ) = readsignconf(signconffname, "pseudo")
            importkeys(session, keys)
            newsignconf = mergesignconf(signconf, keys, signconffname)
            writesignconf(newsignconf, signconffname, "new")
            session.close()
    except pkcs11.exceptions.NoSuchToken:
        print("Unable to access token", file=sys.stderr)
        sys.exit(1)

class KeyNotFound(Exception):
    message = None

    def __init__(self, message):
        self.message = message

def readconf(conffname, zonename, repoindex=None):
    global tokenmodule
    global tokenlabel
    global tokenpin
    global signconffname

    confdoc = xml.dom.minidom.parse(conffname)
    count = 0
    if repoindex != None:
        for reponode in getxpath(confdoc, ['Configuration', 'RepositoryList']).getElementsByTagName('Repository'):
            if count == repoindex:
                tokenmodule = getxpath(reponode, ['Module', None])
                tokenlabel  = getxpath(reponode, ['TokenLabel', None])
                tokenpin    = getxpath(reponode, ['PIN', None])
            count = count + 1
    zonelistfile = getxpath(confdoc, ['Configuration', 'Enforcer', 'WorkingDirectory', None], "") + "/" + "zones.xml"
    if not os.path.exists(zonelistfile):
        zonelistfile = getxpath(confdoc, ['Configuration', 'Common', 'ZoneListFile', None])
    zonelistdoc = xml.dom.minidom.parse(zonelistfile)
    signconffname = None
    for zonenode in getxpath(zonelistdoc, ['ZoneList']).getElementsByTagName('Zone'):
        if zonenode.getAttribute('name') == zonename:
            signconffname = getxpath(zonenode, ['SignerConfiguration', None])

def importkey(session, keyname, modulus, exponent):
    attrs = { }
    attrs[pkcs11.constants.Attribute.ID] = binascii.a2b_hex(keyname)
    for handle in session.get_objects(attrs):
        if isinstance(handle, pkcs11.PublicKey):
            print("Found public key")
            return False
        elif isinstance(handle, pkcs11.PrivateKey):
            print("Found private key")
            return False
    flags  = pkcs11.constants.MechanismFlag.SIGN | pkcs11.constants.MechanismFlag.VERIFY
    flags |= pkcs11.constants.MechanismFlag.WRAP | pkcs11.constants.MechanismFlag.ENCRYPT
    flags |= pkcs11.constants.MechanismFlag.UNWRAP | pkcs11.constants.MechanismFlag.DECRYPT
    flags |= pkcs11.constants.MechanismFlag.HW | pkcs11.constants.MechanismFlag.DIGEST
    template  = { pkcs11.constants.Attribute.TOKEN: True, pkcs11.constants.Attribute.PRIVATE: False }
    template[pkcs11.constants.Attribute.LABEL]  = keyname
    template[pkcs11.constants.Attribute.ID]     = binascii.a2b_hex(keyname)
    template[pkcs11.constants.Attribute.CLASS]          = pkcs11.ObjectClass.PUBLIC_KEY
    template[pkcs11.constants.Attribute.KEY_TYPE]       = pkcs11.KeyType.RSA
    template[pkcs11.constants.Attribute.TOKEN]          = True
    template[pkcs11.constants.Attribute.PRIVATE]        = True
    template[pkcs11.constants.Attribute.ENCRYPT]        = True
    template[pkcs11.constants.Attribute.VERIFY]         = True
    template[pkcs11.constants.Attribute.VERIFY_RECOVER] = True
    template[pkcs11.constants.Attribute.WRAP]           = True
    template[pkcs11.constants.Attribute.MODULUS]         = modulus
    template[pkcs11.constants.Attribute.PUBLIC_EXPONENT] = exponent
    key = session.create_object(template)
    template  = { pkcs11.constants.Attribute.TOKEN: True, pkcs11.constants.Attribute.PRIVATE: False }
    template[pkcs11.constants.Attribute.LABEL]  = keyname
    template[pkcs11.constants.Attribute.ID]     = binascii.a2b_hex(keyname)
    template[pkcs11.constants.Attribute.CLASS]          = pkcs11.ObjectClass.PRIVATE_KEY
    template[pkcs11.constants.Attribute.KEY_TYPE]       = pkcs11.KeyType.RSA
    template[pkcs11.constants.Attribute.TOKEN]          = True
    template[pkcs11.constants.Attribute.PRIVATE]        = True
    template[pkcs11.constants.Attribute.DECRYPT]        = True
    template[pkcs11.constants.Attribute.SIGN]         = True
    template[pkcs11.constants.Attribute.SIGN_RECOVER] = True
    template[pkcs11.constants.Attribute.UNWRAP]         = True
    template[pkcs11.constants.Attribute.MODULUS]          = modulus
    template[pkcs11.constants.Attribute.PRIVATE_EXPONENT] = exponent
    key = session.create_object(template)
    return True

def importkeys(session, keys):
    for keyname in keys.keys():
        if 'keydata' in keys[keyname].keys():
            keydata = base64.b64decode(keys[keyname]['keydata'])
            ( modulus, exponent ) = decomposekeydata(keydata)
            imported = importkey(session, keyname, modulus, exponent)
            if imported:
                print("imported key " + keyname)

def exportkey(session, keyname):
    attrs = { }
    attrs[pkcs11.constants.Attribute.ID] = binascii.a2b_hex(keyname)
    modulus = False
    exponent = False
    for handle in session.get_objects(attrs):
        if isinstance(handle, pkcs11.PublicKey):
            modulus = handle[pkcs11.constants.Attribute.MODULUS]
            exponent = handle[pkcs11.constants.Attribute.PUBLIC_EXPONENT]
            return ( modulus, exponent )
        elif isinstance(handle, pkcs11.PrivateKey):
            modulus = handle[pkcs11.constants.Attribute.MODULUS]
            exponent = handle[pkcs11.constants.Attribute.PUBLIC_EXPONENT]
    if modulus == False:
        raise KeyNotFound(keyname)
    return ( modulus, exponent )

def exportkeys(session, keys):
    for keyname in keys.keys():
        try:
            ( modulus, exponent ) = exportkey(session, keyname)
            keys[keyname] = { 'modulus': modulus,
                              'exponent': exponent,
                              'keydata': composekeydata(modulus, exponent) }
        except KeyNotFound:
            print("key "+keyname+" not found")
            pass

def composekeydata(modulus, exponent):
    modulus_skip = 0
    while modulus_skip < len(modulus) and modulus[modulus_skip] == 0:
        ++modulus_skip                 
    exponent_skip = 0
    while exponent_skip < len(exponent) and exponent[exponent_skip] == 0:       
        ++exponent_skip
    if len(exponent) - exponent_skip > 65535:
        raise Burned("len exponent longer than allowed ("+len(exponent)+")") 
    elif len(exponent) - exponent_skip > 255:
        buffer = bytearray()
        buffer.append(0)
        buffer.append((len(exponent) - exponent_skip) >> 8)
        buffer.append((len(exponent) - exponent_skip) & 0xff)
        buffer.extend(exponent[exponent_skip:])
        buffer.extend(modulus[modulus_skip:]) 
    else:
        buffer = bytearray()
        buffer.append(len(exponent) - exponent_skip)
        buffer.extend(exponent[exponent_skip:])
        buffer.extend(modulus[modulus_skip:])
    return buffer

def decomposekeydata(buffer):
    if buffer[0] == 0:                
        exponent_len = buffer[1] << 8 | buffer[2]
        exponent = buffer[3:exponent_len+3]
        modulus = buffer[exponent_len+3:]
    else:
        exponent_len = buffer[0]
        exponent = buffer[1:exponent_len+1]
        modulus = buffer[exponent_len+1:]
    return ( modulus, exponent )

def processkeys(keys):
    for keyname in keys:
        key = keys[keyname]
        if 'modulus' in key:
            key['keydata'] = composekeydata(key['modulus'], key['exponent'])

def readsignconf(signconf, prefix=None):
    signconfkeys = { }
    if prefix == None:
        fname = signconf
    else:
        fname = os.path.join(os.path.dirname(signconf), prefix + "-" + os.path.basename(signconf))
    doc = xml.dom.minidom.parse(fname)
    for keynode in doc.getElementsByTagName('Key'):
        keyname = getxpath(keynode, ['Locator', None])
        signconfkeys[keyname] = { }
        signconfkeys[keyname]['keynode'] = keynode
        keydata = getxpath(keynode, ['PublicKeyData', None])
        signconfkeys[keyname]['keydata'] = keydata
    return ( doc, signconfkeys )

def getxpath(node, path, defaultValue=None):
    for p in path:
        next = None
        for n in node.childNodes:
            if p == None:
                return n.data
            elif n.localName == p:
                next = n
                break
        if next == None:
            return defaultValue
        else:
            node = next
    return node

def mergesignconf(signconf, keys, fname, prefix=None):
    if prefix != None:
        fname = os.path.join(os.path.dirname(signconf), prefix + "-" + os.path.basename(signconf))
    doc = xml.dom.minidom.parse(fname)
    keysnode = getxpath(doc, ['SignerConfiguration', 'Zone', 'Keys'])
    for key in keys:
        keynode = keys[key]['keynode']
        locator = getxpath(keynode, ["Locator"])
        if locator in keys:
            keysnode.removeChild(keynode)
    for key in keys:
        mergekeyrolenum = getxpath(keys[key]['keynode'], ['Flags', None])
        mergekeyalgonum = getxpath(keys[key]['keynode'], ['Algorithm', None])
        mergekeylocator = getxpath(keys[key]['keynode'], ['Locator', None])
        #mergekeyksk     = getxpath(keys[key]['keynode'], ['KSK'])
        #mergekeyzsk     = getxpath(keys[key]['keynode'], ['ZSK'])
        mergekeypublish = getxpath(keys[key]['keynode'], ['Publish'])
        keynode = doc.createElement("Key")
        keynode.appendChild(doc.createTextNode("\n\t\t\t\t"))
        node = doc.createElement("Flags")
        node.appendChild(doc.createTextNode(str(mergekeyrolenum)))
        keynode.appendChild(node)
        keynode.appendChild(doc.createTextNode("\n\t\t\t\t"))
        node = doc.createElement("Algorithm")
        node.appendChild(doc.createTextNode(str(mergekeyalgonum)))
        keynode.appendChild(doc.createTextNode("\n\t\t\t\t"))
        keynode.appendChild(node)
        node = doc.createElement("Locator")
        node.appendChild(doc.createTextNode(str(mergekeylocator)))
        keynode.appendChild(node)
        #if mergekeyksk != None:
        #    node = doc.createElement("KSK")
        #    keynode.appendChild(node)
        #    keynode.appendChild(doc.createTextNode("\n              "))
        #if mergekeyzsk != None:
        #    node = doc.createElement("ZSK")
        #    keynode.appendChild(node)
        #    keynode.appendChild(doc.createTextNode("\n\t\t\t\t"))
        if mergekeypublish != None:
            node = doc.createElement("Publish")
            keynode.appendChild(doc.createTextNode("\n\t\t\t\t"))
            keynode.appendChild(node)
        keynode.appendChild(doc.createTextNode("\n\t\t\t"))
        keysnode.appendChild(doc.createTextNode("\t"))
        keysnode.appendChild(keynode)
        keysnode.appendChild(doc.createTextNode("\n\t\t"))
    return doc

def writesignconf(doc, signconf, prefix=None):
    if prefix == None:
        fname = signconf
    else:
        fname = os.path.join(os.path.dirname(signconf), prefix + "-" + os.path.basename(signconf))
    with open(fname, "w") as f:
        print(doc.toprettyxml(newl="",indent=""), file=f)

def patchsignconf(doc, signconfkeys):
    for keys in doc.getElementsByTagName('Keys'):
        for key in keys.getElementsByTagName('Key'):
            for locator in key.getElementsByTagName('Locator'):
                keyname = locator.childNodes[0].data
                if keyname in signconfkeys and 'keydata' in signconfkeys[keyname]:
                    keydata = base64.b64encode(signconfkeys[keyname]['keydata'])
                    # del signconfkeys[keyname]
                    node = doc.createElement("PublicKeyData")
                    node.appendChild(doc.createTextNode(keydata.decode('ascii')))
                    key.appendChild(doc.createTextNode("	"))
                    key.appendChild(node)
                    key.appendChild(doc.createTextNode("\n			"))
                else:
                    keys.removeChild(key)
                break

'''
Main program, In principe this module could be used from another program in
which case no action is taken unless a method is explicitly called.
'''
if __name__ == "__main__":
    result = main()
    if result != 0:
        sys.exit(result)
