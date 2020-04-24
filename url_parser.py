#-*- coding: utf-8 -*-
import os, re, sys, time, shutil
import xml.etree.ElementTree as ET

doc = []
save = []
xml_path = []
xmlfile = []
URL = []

fol_path = sys.argv[1]

scanner_path = os.path.dirname(os.path.realpath(__file__))

a = os.getenv("appdata")[:-8]

result_path= a+'\Local\Temp\DecompressedMsOfficeDocument\word\_rels'

py_version = re.search("major=(.*), minor",str(sys.version_info))


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
    #if py_version.group(1) == '2':
    #    sys.stdout = open(fol_path+'\\result.txt', 'w')
    #else:
    #    sys.stdout = open(fol_path+'\\result.txt', 'w', -1, 'utf-8')
        
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
        os.popen('cd /d %s & OfficeMalScanner.exe %s\\%s inflate' % (scanner_path, fol_path, i) )
        time.sleep(0.3)
        if os.path.isdir(result_path) == True:
            xml_scan(result_path)
            xml_url_parser(result_path)
            #del xmlfile[:]
            del xml_path[:]
            print('------------------------------------------------------------------------------------------------')
            print('[+]MD5 : %s' % i)
            for out in save:
                print('[+]URL : %s' % out.encode('utf-8'))
                print('------------------------------------------------------------------------------------------------')
                del save[:]
                shutil.rmtree(result_path[:-11])
        else:
            print('------------------------------------------------------------------------------------------------')
            print('[+]MD5 : %s' % i)
            print('[+]URL : Not URL')
            print('------------------------------------------------------------------------------------------------')
            pass
        
      

def xml_scan(result_path):
    xml_file = os.listdir(result_path)
    for filename in xml_file:
        xml_path.append(filename)
        
    '''    
    setting_xml = re.search('settings.xml.rels', ''.join(xml_path))
    docu_xml = re.search('document.xml.rels', ''.join(xml_path))
    if docu_xml != None:
        if setting_xml != None:
            xmlfile.append(setting_xml.group())
        else:
            xmlfile.append(docu_xml.group())
    else:
        print('not xml.rels file')
    '''
    
    

#CVE-2017-0199
def xml_url_parser(result_path):
    for xmlfile in xml_path:
        xml = ET.parse(result_path+'\\'+xmlfile)
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
    #for save_value in save:
    #    URL.append(save_value)       



doc_scan(fol_path)
malscan()
#xml_scan(result_path)
#xml_url_parser(result_path)


#sys.stdout = open(fol_path+'\\result.txt', 'w')
#for out in save:
#    print(out)
