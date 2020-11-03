import os 

#==================PATH==================
SCANNER_PATH = os.path.dirname(os.path.realpath(__file__))
APPDATA_PATH = os.getenv("appdata")[:-8]
UNZIP_PATH = os.path.join(APPDATA_PATH, 'Local', 'Temp', 'DecompressedMsOfficeDocument')
RELS_PATH = os.path.join(UNZIP_PATH, 'word', '_rels')
