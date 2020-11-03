#-*- coding: utf-8 -*-
import os
import re
import sys
import time
import shutil
import pyzipper
import xml.etree.ElementTree as ET

from settings import *

doc = []
save = []
xml_path = []
xmlfile = []
URL = []

FOL_PATH = sys.argv[1]

py_version = re.search("major=(.*), minor",str(sys.version_info))

def Unpack_zipfile(filename):
    try:
        #Unpack_zipfile
        #Create folder(zipfilename) 
        file_path = os.path.join(FOL_PATH, filename)
        with pyzipper.AESZipFile(file_path) as zf:
            my_secrets = zf.extractall(UNZIP_PATH)             
            print("Sample downloaded and unpacked.")
    except Exception as e:   
        print("Not find %s" % filename)

def doc_scan(fol_path):
    doc_file = os.listdir(fol_path)
    if len(doc_file) != 0:
        for filename in doc_file:
            if filename != 'result.txt':
                doc.append(filename)
    else:
        print('please put file on %s folder ' % fol_path)
        sys.exit(1)


def malscan():
       
    print('''
 ██████╗██╗   ██╗███████╗    ██████╗  ██████╗  ██╗███████╗       ██████╗  ██╗ █████╗  █████╗ 
██╔════╝██║   ██║██╔════╝    ╚════██╗██╔═████╗███║╚════██║      ██╔═████╗███║██╔══██╗██╔══██╗
██║     ██║   ██║█████╗█████╗ █████╔╝██║██╔██║╚██║    ██╔╝█████╗██║██╔██║╚██║╚██████║╚██████║
██║     ╚██╗ ██╔╝██╔══╝╚════╝██╔═══╝ ████╔╝██║ ██║   ██╔╝ ╚════╝████╔╝██║ ██║ ╚═══██║ ╚═══██║
╚██████╗ ╚████╔╝ ███████╗    ███████╗╚██████╔╝ ██║   ██║        ╚██████╔╝ ██║ █████╔╝ █████╔╝
 ╚═════╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝  ╚═╝   ╚═╝         ╚═════╝  ╚═╝ ╚════╝  ╚════╝ 
                                                                                             
''')
    print('Console Tool and Python 2.x, 3.x DOC Malware Scanner version 1.0')
    for i in doc:
        Unpack_zipfile(i)
        #time.sleep(0.3)
        if os.path.isdir(RELS_PATH) == True:
            xml_scan(RELS_PATH)
            xml_url_parser(RELS_PATH)
            del xml_path[:]
            print('------------------------------------------------------------------------------------------------')
            print('[+]MD5 : %s' % i)
            if save:
                for out in save:
                    print(out)
                    print('[+]URL : %s' % out.encode('utf-8'))
                    print('------------------------------------------------------------------------------------------------')
                    del save[:]
                    shutil.rmtree(RELS_PATH[:-11])
            else:
                print('[+]URL : Not URL')
                print('------------------------------------------------------------------------------------------------')
                
        else:
            print('------------------------------------------------------------------------------------------------')
            print('[+]MD5 : %s' % i)
            print('[+]URL : Not URL')
            print('------------------------------------------------------------------------------------------------')
            pass
        
      

def xml_scan(rels_path):
    xml_file = os.listdir(rels_path)
    for filename in xml_file:
        xml_path.append(filename)

          

#CVE-2017-0199
def xml_url_parser(rels_path):
    for xmlfile in xml_path:
        xml = ET.parse(rels_path+'\\'+xmlfile)
        root = xml.getroot()

        for Data in root:
            texts = Data.attrib
            key_value = texts.get('TargetMode')
            if key_value != None and key_value =='External':
                url = texts.get('Target')
                noturl = re.search('(mailto:).*',url)
                if noturl == None:
                    save.append(url)
                else:
                    pass
    

#main
doc_scan(FOL_PATH)
malscan()

