# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, IMessageEditorTabFactory, IMessageEditorTab, ITab
from javax.swing import (JPanel, JButton, JTextArea, JScrollPane, JFileChooser, JOptionPane, 
                         BorderFactory, JTable, JLabel, SwingConstants, Box, BoxLayout, JSplitPane)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout, Dimension, Color, Font, GridLayout, FlowLayout
from java.awt.event import MouseAdapter
from java.io import FileInputStream, File as JFile
import re

class BurpExtender(IBurpExtender, IHttpListener, IMessageEditorTabFactory):
    
    # Storage for file mappings
    file_mappings = {}
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("File Upload Tag Manager")
        
        # Register HTTP listener to process requests
        callbacks.registerHttpListener(self)
        
        # Register message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)
        
        print("File Upload Tag Extension Loaded!")
        print("")
        print("=" * 70)
        print("  FILE UPLOAD TAG EXTENSION - FEATURES")
        print("=" * 70)
        print("")
        print("1. FILE UPLOAD TAGS:")
        print("   Use these tags in your request body to upload files:")
        print("")
        print("   <@getfile@>           - Upload file as raw binary")
        print("   <@getfile1@>          - Upload second file as raw binary")
        print("   <@getfile2@>          - Upload third file as raw binary")
        print("   <@getfileN@>          - Upload Nth file (N = any number)")
        print("")
        print("2. BASE64 ENCODING:")
        print("   Add ':base64' modifier to encode file content:")
        print("")
        print("   <@getfile:base64@>    - Upload file encoded in base64")
        print("   <@getfile1:base64@>   - Upload second file encoded in base64")
        print("   <@getfile2:base64@>   - Upload third file encoded in base64")
        print("")
        print("3. AUTO CONTENT-TYPE DETECTION:")
        print("   Use typefile tags to auto-fill Content-Type headers:")
        print("")
        print("   <@typefile@>          - Auto-detect Content-Type for getfile")
        print("   <@typefile1@>         - Auto-detect Content-Type for getfile1")
        print("   <@typefile2@>         - Auto-detect Content-Type for getfile2")
        print("")
        print("   Supported 130+ file formats:")
        print("   - Web: PHP, ASP, JSP, ColdFusion, HTML, JS, XML")
        print("   - Scripts: Python, Perl, Bash, PowerShell")
        print("   - Documents: PDF, Word, Excel, CSV, JSON, TXT")
        print("   - Images: JPG, PNG, GIF, BMP, SVG, TIFF, RAW, ICO")
        print("   - Audio: MP3, WAV, AAC, FLAC, OGG, M4A, WMA")
        print("   - Video: MP4, AVI, MKV, MOV, WMV, FLV, WEBM, MPEG")
        print("   - Archives: ZIP, RAR, TAR, GZ, 7Z, JAR")
        print("")
        print("4. HOW TO USE:")
        print("   a) Add tags to your request in Repeater/Intruder")
        print("   b) Go to 'File Tags' tab in the request editor")
        print("   c) Click 'Select File' button to choose file from your computer")
        print("   d) Send request - tags will be replaced automatically")
        print("")
        print("5. EXAMPLE MULTIPART REQUEST:")
        print("   ------WebKitFormBoundary123")
        print("   Content-Disposition: form-data; name=\"File\"; filename=\"doc.xlsx\"")
        print("   Content-Type: <@typefile@>")
        print("")
        print("   <@getfile@>")
        print("   ------WebKitFormBoundary123--")
        print("")
        print("6. EXAMPLE JSON REQUEST:")
        print("   {")
        print("     \"filename\": \"document.pdf\",")
        print("     \"content\": \"<@getfile:base64@>\",")
        print("     \"contentType\": \"<@typefile@>\"")
        print("   }")
        print("")
        print("=" * 70)
        print("Extension ready! Go to Repeater -> File Tags tab to get started.")
        print("=" * 70)
    
    def formatBytes(self, size):
        """Format file size in human readable format"""
        if size < 1024:
            return str(size) + " B"
        elif size < 1024 * 1024:
            return str(round(size / 1024.0, 2)) + " KB"
        elif size < 1024 * 1024 * 1024:
            return str(round(size / (1024.0 * 1024), 2)) + " MB"
        else:
            return str(round(size / (1024.0 * 1024 * 1024), 2)) + " GB"
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only process requests
        if not messageIsRequest:
            return
        
        try:
            # Get request bytes
            request = messageInfo.getRequest()
            requestInfo = self._helpers.analyzeRequest(request)
            
            # Convert to string for pattern matching
            requestStr = self._helpers.bytesToString(request)
            
            # Find all tags in format <@getfile@>, <@getfile1@>, <@getfile:base64@>, etc.
            # Only accept: getfile, getfile1, getfile2, ... getfile999
            pattern = r'<@(getfile\d*)(?::([^@]+))?@>'
            matches = list(re.finditer(pattern, requestStr))
            
            # Also find typefile tags for Content-Type replacement
            typefilePattern = r'<@(typefile\d*)(?::([a-zA-Z0-9]+))?@>'
            typefileMatches = list(re.finditer(typefilePattern, requestStr))
            
            if len(matches) == 0 and len(typefileMatches) == 0:
                return
            
            modified = False
            newRequest = request
            
            # Collect all getfile tags with their info in ORDER
            getfileInfos = []
            for match in matches:
                paramName = match.group(1)
                encoding = match.group(2) if match.group(2) else None
                tag = match.group(0)
                
                if paramName in BurpExtender.file_mappings:
                    filePath = BurpExtender.file_mappings[paramName]
                    getfileInfos.append({
                        'tag': tag,
                        'paramName': paramName,
                        'filePath': filePath,
                        'encoding': encoding
                    })
            
            # Process each getfile tag in order
            for info in getfileInfos:
                try:
                    # Read file content
                    fileContent = self.readFileAsBytes(info['filePath'])
                    
                    # Apply encoding if specified
                    if info['encoding'] == "base64":
                        # Convert byte array to base64 string
                        from org.python.core.util import StringUtil
                        import base64
                        
                        # Convert Java byte array to Python string for base64 encoding
                        byteString = ""
                        for b in fileContent:
                            if b < 0:
                                byteString += chr(b + 256)
                            else:
                                byteString += chr(b)
                        
                        # Encode to base64
                        encodedStr = base64.b64encode(byteString)
                        
                        # Convert base64 string back to byte array
                        from java.lang import String
                        encodedBytes = []
                        for b in String(encodedStr).getBytes("UTF-8"):
                            if b > 127:
                                encodedBytes.append(b - 256)
                            else:
                                encodedBytes.append(b)
                        
                        from jarray import array
                        fileContent = array(encodedBytes, 'b')
                    
                    # Replace getfile tag with file content
                    newRequest = self.replaceInRequest(newRequest, info['tag'], fileContent)
                    modified = True
                    
                except Exception as e:
                    print("ERROR: Failed to process file for " + info['tag'] + ": " + str(e))
            
            # Update requestStr after getfile replacements to ensure correct offsets/content for typefile
            requestStr = self._helpers.bytesToString(newRequest)
            
            # Now replace ALL typefile tags in the updated request
            # Support both auto-detection <@typefile@> and explicit extension <@typefile:php@>
            
            # Find all typefile tags: <@typefile[digits][:extension]@>
            typefilePattern = r'<@(typefile\d*)(?::([^@]+))?@>'
            typefileMatches = list(re.finditer(typefilePattern, requestStr))
            
            # Get unique tags to process
            uniqueTypefileTags = set()
            for m in typefileMatches:
                uniqueTypefileTags.add(m.group(0))
            
            for tag in uniqueTypefileTags:
                # Parse tag again to get details
                match = re.match(typefilePattern, tag)
                if match:
                    baseName = match.group(1) # e.g. typefile, typefile1
                    overrideExt = match.group(2) # e.g. php, or None
                    
                    contentType = None
                    
                    if overrideExt:
                        # Case 1: Explicit extension override
                        # We pass a dummy filename with that extension to getContentType
                        contentType = self.getContentType("dummy." + overrideExt)
                    else:
                        # Case 2: Auto-detect from corresponding getfile
                        # We need to find which getfile corresponds to this typefile
                        # typefile -> getfile, typefile1 -> getfile1
                        getfileParamName = baseName.replace("typefile", "getfile")
                        
                        # Find this param in getfileInfos
                        for info in getfileInfos:
                            if info['paramName'] == getfileParamName:
                                contentType = self.getContentType(info['filePath'])
                                break
                    
                    if contentType:
                        # Replace ALL occurrences of this specific tag
                        while tag in requestStr:
                            contentTypeBytes = self._helpers.stringToBytes(contentType)
                            newRequest = self.replaceInRequest(newRequest, tag, contentTypeBytes)
                            requestStr = self._helpers.bytesToString(newRequest)
                            modified = True
            
            # Update request if modified
            if modified:
                # Update Content-Length header
                newRequest = self.updateContentLength(newRequest)
                messageInfo.setRequest(newRequest)
                
        except Exception as e:
            print("ERROR in processHttpMessage: " + str(e))
    
    def readFileAsBytes(self, filePath):
        """Read file and return as byte array"""
        jfile = JFile(filePath)
        fis = FileInputStream(jfile)
        fileBytes = []
        
        byte = fis.read()
        while byte != -1:
            if byte > 127:
                fileBytes.append(byte - 256)  # Convert to signed byte
            else:
                fileBytes.append(byte)
            byte = fis.read()
        fis.close()
        
        from jarray import array
        return array(fileBytes, 'b')
    
    def replaceInRequest(self, request, tag, replacement):
        """Replace tag in request with file content - Improved version"""
        try:
            # Convert request to string first
            requestStr = self._helpers.bytesToString(request)
            
            # Check if tag exists
            if tag not in requestStr:
                return request
            
            # Find tag position in string
            tagPos = requestStr.find(tag)
            
            # Split request into parts: before tag, and after tag
            beforeTag = requestStr[:tagPos]
            afterTag = requestStr[tagPos + len(tag):]
            
            # Convert parts to bytes
            from java.lang import String
            beforeBytes = []
            for b in String(beforeTag).getBytes("ISO-8859-1"):
                if b > 127:
                    beforeBytes.append(b - 256)
                else:
                    beforeBytes.append(b)
            
            afterBytes = []
            for b in String(afterTag).getBytes("ISO-8859-1"):
                if b > 127:
                    afterBytes.append(b - 256)
                else:
                    afterBytes.append(b)
            
            # Combine: before + replacement + after
            resultBytes = []
            resultBytes.extend(beforeBytes)
            resultBytes.extend(replacement)
            resultBytes.extend(afterBytes)
            
            # Convert to byte array
            from jarray import array
            result = array(resultBytes, 'b')
            
            return result
            
        except Exception as e:
            print("ERROR in replaceInRequest: " + str(e))
            return request
    
    def findSubArray(self, haystack, needle):
        """Find position of needle in haystack"""
        for i in range(len(haystack) - len(needle) + 1):
            match = True
            for j in range(len(needle)):
                if haystack[i + j] != needle[j]:
                    match = False
                    break
            if match:
                return i
        return -1
    
    def updateContentLength(self, request):
        """Update Content-Length header to match actual body size"""
        try:
            requestInfo = self._helpers.analyzeRequest(request)
            headers = list(requestInfo.getHeaders())
            bodyOffset = requestInfo.getBodyOffset()
            
            # Calculate new body length
            bodyLength = len(request) - bodyOffset
            
            # Update or add Content-Length header
            newHeaders = []
            contentLengthFound = False
            
            for header in headers:
                headerLower = header.lower()
                if headerLower.startswith("content-length:"):
                    newHeaders.append("Content-Length: " + str(bodyLength))
                    contentLengthFound = True
                else:
                    newHeaders.append(header)
            
            # Add Content-Length if not found
            if not contentLengthFound:
                newHeaders.append("Content-Length: " + str(bodyLength))
            
            # Get body
            body = []
            for i in range(bodyOffset, len(request)):
                body.append(request[i])
            
            # Build new request with updated headers
            from jarray import array
            bodyArray = array(body, 'b')
            
            result = self._helpers.buildHttpMessage(newHeaders, bodyArray)
            return result
            
        except Exception as e:
            print("ERROR in updateContentLength: " + str(e))
            return request
    
    def getContentType(self, filePath):
        """Get Content-Type based on file extension"""
        ext = filePath.lower().split('.')[-1] if '.' in filePath else ''
        
        content_types = {
            # PHP
            'php': 'application/x-httpd-php',
            'php2': 'application/x-httpd-php',
            'php3': 'application/x-httpd-php',
            'php4': 'application/x-httpd-php',
            'php5': 'application/x-httpd-php',
            'php6': 'application/x-httpd-php',
            'php7': 'application/x-httpd-php',
            'phps': 'application/x-httpd-php-source',
            'pht': 'application/x-httpd-php',
            'phtm': 'application/x-httpd-php',
            'phtml': 'text/html',
            'pgif': 'image/gif',
            'shtml': 'text/html',
            'htaccess': 'text/plain',
            'phar': 'application/octet-stream',
            'inc': 'text/plain',
            
            # ASP
            'asp': 'text/asp',
            'aspx': 'text/asp',
            'config': 'application/xml',
            'ashx': 'text/plain',
            'asmx': 'text/plain',
            'aspq': 'text/asp',
            'axd': 'text/plain',
            'cshtm': 'text/html',
            'cshtml': 'text/html',
            'rem': 'text/plain',
            'soap': 'application/soap+xml',
            'vbhtm': 'text/html',
            'vbhtml': 'text/html',
            'asa': 'text/plain',
            'cer': 'application/x-x509-ca-cert',
            'shtml': 'text/html',
            
            # JSP
            'jsp': 'text/html',
            'jspx': 'text/html',
            'jsw': 'text/html',
            'jsv': 'text/html',
            'jspf': 'text/html',
            'wss': 'text/html',
            'do': 'text/html',
            'action': 'text/html',
            
            # ColdFusion
            'cfm': 'text/html',
            'cfml': 'text/html',
            'cfc': 'text/html',
            'dbm': 'text/html',
            
            # Flash
            'swf': 'application/x-shockwave-flash',
            
            # Perl
            'pl': 'text/x-perl',
            'cgi': 'text/plain',
            
            # Erlang
            'yaws': 'text/html',
            
            # HTML
            'html': 'text/html',
            'htm': 'text/html',
            'js': 'application/javascript',
            'xml': 'application/xml',
            
            # Python
            'py': 'text/x-python',
            'py3': 'text/x-python',
            'pyc': 'application/x-python-code',
            'pyo': 'application/x-python-code',
            'pyw': 'text/x-python',
            'pyx': 'text/x-python',
            'pyd': 'application/octet-stream',
            'pxd': 'text/x-python',
            'pxi': 'text/x-python',
            'pyi': 'text/x-python',
            'pyz': 'application/zip',
            'pywz': 'application/zip',
            'pth': 'text/plain',
            
            # Bash Script
            'sh': 'application/x-sh',
            'exe': 'application/x-msdownload',
            'ps1': 'text/plain',
            'psd1': 'text/plain',
            'psm1': 'text/plain',
            'ps1xml': 'text/xml',
            'bat': 'application/x-bat',
            'dll': 'application/x-msdownload',
            'txt': 'text/plain',
            'bin': 'application/octet-stream',
            'msi': 'application/x-msi',
            'jar': 'application/java-archive',
            
            # Images
            'tif': 'image/tiff',
            'tiff': 'image/tiff',
            'bmp': 'image/bmp',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'gif': 'image/gif',
            'png': 'image/png',
            'eps': 'application/postscript',
            'raw': 'image/x-raw',
            'cr2': 'image/x-canon-cr2',
            'nef': 'image/x-nikon-nef',
            'orf': 'image/x-olympus-orf',
            'sr2': 'image/x-sony-sr2',
            'svg': 'image/svg+xml',
            'ico': 'image/x-icon',
            
            # Documents
            'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'xls': 'application/vnd.ms-excel',
            'pdf': 'application/pdf',
            'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'csv': 'text/csv',
            'json': 'application/json',
            
            # Archives
            'zip': 'application/zip',
            'rar': 'application/x-rar-compressed',
            'tar': 'application/x-tar',
            'gz': 'application/gzip',
            '7z': 'application/x-7z-compressed',
            
            # Audio
            'mp3': 'audio/mpeg',
            'wav': 'audio/wav',
            'wma': 'audio/x-ms-wma',
            'aac': 'audio/aac',
            'flac': 'audio/flac',
            'ogg': 'audio/ogg',
            'm4a': 'audio/mp4',
            'oga': 'audio/ogg',
            'opus': 'audio/opus',
            'weba': 'audio/webm',
            'mid': 'audio/midi',
            'midi': 'audio/midi',
            
            # Video
            'mp4': 'video/mp4',
            'avi': 'video/x-msvideo',
            'mkv': 'video/x-matroska',
            'mov': 'video/quicktime',
            'wmv': 'video/x-ms-wmv',
            'flv': 'video/x-flv',
            'webm': 'video/webm',
            'mpeg': 'video/mpeg',
            'mpg': 'video/mpeg',
            'm4v': 'video/x-m4v',
            '3gp': 'video/3gpp',
            '3g2': 'video/3gpp2',
            'ogv': 'video/ogg',
            'ts': 'video/mp2t',
            'vob': 'video/dvd',
            'rm': 'application/vnd.rn-realmedia',
            'rmvb': 'application/vnd.rn-realmedia-vbr',
            'asf': 'video/x-ms-asf'
        }
        
        return content_types.get(ext, 'application/octet-stream')
    
    def createNewInstance(self, controller, editable):
        return FileUploadTagEditorTab(self, controller, editable)


class NonEditableModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False

class DoubleClickListener(MouseAdapter):
    def __init__(self, action_listener):
        self.action_listener = action_listener
    
    def mouseClicked(self, event):
        if event.getClickCount() == 2:
            self.action_listener(event)

class FileUploadTagEditorTab(IMessageEditorTab):
    """Custom editor tab to show which tags will be replaced"""
    
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._controller = controller
        self._editable = editable
        self._currentMessage = None
        
        # Create UI
        self.panel = JPanel(BorderLayout(10, 10))
        self.panel.setBorder(EmptyBorder(10, 10, 10, 10))
        
        # Table
        self.tableModel = NonEditableModel(
            ["Tag Name", "File Path", "File Size", "Content-Type", "Status"], 0
        )
        self.table = JTable(self.tableModel)
        self.table.addMouseListener(DoubleClickListener(self.reloadFile))
        self.table.setRowHeight(25)
        self.table.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.table.getTableHeader().setFont(Font("Dialog", Font.BOLD, 12))
        
        # Selection listener
        self.table.getSelectionModel().addListSelectionListener(self.onSelectionChanged)
        
        tableScrollPane = JScrollPane(self.table)
        
        # Reference Info
        referenceText = (
            "CONTENT-TYPE MAPPING REFERENCE (Used by <@typefile@> tags):\n"
            "-----------------------------------------------------------------------------------\n"
            " PHP         : .php, .php2-7, .pht, .phtm -> application/x-httpd-php\n"
            "               .phps -> application/x-httpd-php-source\n"
            "               .phtml, .shtml -> text/html | .pgif -> image/gif\n"
            "               .phar -> application/octet-stream | .inc, .htaccess -> text/plain\n"
            "\n"
            " ASP/.NET    : .asp, .aspx, .aspq -> text/asp\n"
            "               .ashx, .asmx, .axd, .asa, .rem -> text/plain\n"
            "               .config -> application/xml | .cer -> application/x-x509-ca-cert\n"
            "               .cshtm, .cshtml, .vbhtm, .vbhtml -> text/html\n"
            "               .soap -> application/soap+xml\n"
            "\n"
            " JSP/Java    : .jsp, .jspx, .jsw, .jsv, .jspf, .wss, .do, .action -> text/html\n"
            "               .jar -> application/java-archive\n"
            "\n"
            " ColdFusion  : .cfm, .cfml, .cfc, .dbm -> text/html\n"
            " Flash       : .swf -> application/x-shockwave-flash\n"
            " Perl        : .pl -> text/x-perl | .cgi -> text/plain\n"
            " Erlang      : .yaws -> text/html\n"
            "\n"
            " Python      : .py, .py3, .pyw, .pyx, .pxd, .pxi, .pyi -> text/x-python\n"
            "               .pyc, .pyo -> application/x-python-code\n"
            "               .pyd -> application/octet-stream | .pyz, .pywz -> application/zip\n"
            "               .pth -> text/plain\n"
            "\n"
            " Shell/Sys   : .sh -> application/x-sh | .bash -> text/x-shellscript\n"
            "               .exe, .dll -> application/x-msdownload | .msi -> application/x-msi\n"
            "               .bat -> application/x-bat | .ps1, .psd1, .psm1 -> text/plain\n"
            "               .ps1xml -> text/xml | .bin -> application/octet-stream\n"
            "\n"
            " Web/Data    : .html, .htm -> text/html | .js -> application/javascript\n"
            "               .xml -> application/xml | .json -> application/json\n"
            "               .csv -> text/csv | .txt -> text/plain\n"
            "\n"
            " Documents   : .pdf -> application/pdf | .doc -> application/msword\n"
            "               .docx -> application/vnd.openxmlformats-officedocument.wordprocessingml.document\n"
            "               .xlsx -> application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\n"
            "               .xls -> application/vnd.ms-excel\n"
            "\n"
            " Images      : .jpg, .jpeg -> image/jpeg | .png -> image/png | .gif -> image/gif\n"
            "               .bmp -> image/bmp | .svg -> image/svg+xml | .ico -> image/x-icon\n"
            "               .tif, .tiff -> image/tiff | .eps -> application/postscript\n"
            "               .raw -> image/x-raw | .cr2 -> image/x-canon-cr2\n"
            "               .nef -> image/x-nikon-nef | .orf -> image/x-olympus-orf\n"
            "               .sr2 -> image/x-sony-sr2\n"
            "\n"
            " Audio       : .mp3 -> audio/mpeg | .wav -> audio/wav | .aac -> audio/aac\n"
            "               .flac -> audio/flac | .ogg, .oga -> audio/ogg | .m4a -> audio/mp4\n"
            "               .wma -> audio/x-ms-wma | .opus -> audio/opus | .weba -> audio/webm\n"
            "               .mid, .midi -> audio/midi\n"
            "\n"
            " Video       : .mp4 -> video/mp4 | .avi -> video/x-msvideo | .mkv -> video/x-matroska\n"
            "               .mov -> video/quicktime | .wmv -> video/x-ms-wmv | .flv -> video/x-flv\n"
            "               .webm -> video/webm | .mpeg, .mpg -> video/mpeg | .m4v -> video/x-m4v\n"
            "               .3gp -> video/3gpp | .3g2 -> video/3gpp2 | .ogv -> video/ogg\n"
            "               .ts -> video/mp2t | .vob -> video/dvd | .asf -> video/x-ms-asf\n"
            "               .rm -> application/vnd.rn-realmedia\n"
            "               .rmvb -> application/vnd.rn-realmedia-vbr\n"
            "\n"
            " Archives    : .zip -> application/zip | .rar -> application/x-rar-compressed\n"
            "               .tar -> application/x-tar | .gz -> application/gzip\n"
            "               .7z -> application/x-7z-compressed\n"
            "\n"
            " Other       : Unknown extensions -> application/octet-stream\n"
        )
        
        infoArea = JTextArea(referenceText)
        infoArea.setFont(Font("Monospaced", Font.PLAIN, 11))
        infoArea.setEditable(False)
        infoArea.setBackground(Color(245, 245, 245))
        infoArea.setCaretPosition(0)
        
        infoScrollPane = JScrollPane(infoArea)
        infoPanel = JPanel(BorderLayout())
        infoPanel.setBorder(BorderFactory.createTitledBorder("Content-Type Mapping Reference"))
        infoPanel.add(infoScrollPane, BorderLayout.CENTER)
        
        # Split Pane
        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScrollPane, infoPanel)
        splitPane.setResizeWeight(0.6) # Give 60% space to table by default
        
        self.panel.add(splitPane, BorderLayout.CENTER)
        
        # Bottom panel for buttons
        self.buttonPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
        
        self.selectFileButton = JButton("Select/Change File", actionPerformed=self.reloadFile)
        self.selectFileButton.setEnabled(False)
        self.selectFileButton.setFont(Font("Dialog", Font.BOLD, 12))
        self.buttonPanel.add(self.selectFileButton)
        
        self.panel.add(self.buttonPanel, BorderLayout.SOUTH)
        
    def onSelectionChanged(self, event):
        if not event.getValueIsAdjusting():
            selectedRow = self.table.getSelectedRow()
            if selectedRow >= 0:
                tagName = self.tableModel.getValueAt(selectedRow, 0)
                # Only enable button for getfile tags (displayed as "getfile...", typefile tags are "<@typefile...>")
                self.selectFileButton.setEnabled(str(tagName).startswith("getfile"))
            else:
                self.selectFileButton.setEnabled(False)

    def getTabCaption(self):
        return "File Tags"
    
    def getUiComponent(self):
        return self.panel
    
    def isEnabled(self, content, isRequest):
        if not isRequest:
            return False
        # Check if content has tags
        if content:
            request_str = self._extender._helpers.bytesToString(content)
            return "<@getfile" in request_str or "<@typefile" in request_str
        return False
    
    def setMessage(self, content, isRequest):
        self._currentMessage = content
        if not isRequest or not content:
            self.tableModel.setRowCount(0)
            return
            
        request_str = self._extender._helpers.bytesToString(content)
        
        # Find tags
        # Find all <@getfile...@> tags
        # We want to capture the base tag name (e.g. getfile, getfile1) ignoring :base64
        matches = re.findall(r'<@(getfile\d*)(?::[a-zA-Z0-9_]+)?@>', request_str)
        
        unique_tags = sorted(list(set(matches)))
        
        self.tableModel.setRowCount(0)
        
        for tag in unique_tags:
            path = BurpExtender.file_mappings.get(tag, "")
            
            status = "Not Mapped"
            fileSize = ""
            contentType = ""
            
            if path:
                jfile = JFile(path)
                if jfile.exists():
                    status = "Ready"
                    fileSize = self._extender.formatBytes(jfile.length())
                    contentType = self._extender.getContentType(path)
                else:
                    status = "File Not Found"
            
            self.tableModel.addRow([tag, path, fileSize, contentType, status])
            
        # Handle typefile tags
        typefile_matches = re.findall(r'<@(typefile\d*)(?::([^@]+))?@>', request_str)
        
        processed_typefiles = set()
        
        for base_name, extension in typefile_matches:
            full_tag = "<@" + base_name + (":" + extension if extension else "") + "@>"
            
            if full_tag in processed_typefiles:
                continue
            processed_typefiles.add(full_tag)
            
            if extension:
                # Static typefile (e.g. <@typefile:php@>)
                ctype = self._extender.getContentType("dummy." + extension)
                self.tableModel.addRow([full_tag, "(Static Type)", "-", ctype, "Ready"])
            else:
                # Dynamic typefile (e.g. <@typefile@>)
                corresponding_getfile = base_name.replace("typefile", "getfile")
                
                if corresponding_getfile not in unique_tags:
                    self.tableModel.addRow([full_tag, "Missing Dependency", "-", "-", "Error: Needs <@" + corresponding_getfile + "@>"])
            
    def reloadFile(self, event):
        """Allow user to select a new file for a parameter"""
        selectedRow = self.table.getSelectedRow()
        if selectedRow < 0:
            return
            
        tagName = self.tableModel.getValueAt(selectedRow, 0)
        
        # Only allow file selection for getfile tags
        if not str(tagName).startswith("getfile"):
            return
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Select file for tag: " + tagName)
        
        # Set initial directory if mapping exists
        currentPath = self.tableModel.getValueAt(selectedRow, 1)
        if currentPath and JFile(currentPath).exists():
            chooser.setSelectedFile(JFile(currentPath))
        
        ret = chooser.showOpenDialog(self.panel)
        if ret == JFileChooser.APPROVE_OPTION:
            f = chooser.getSelectedFile()
            filePath = f.getAbsolutePath()
            
            # Update mapping
            BurpExtender.file_mappings[tagName] = filePath
            
            # Refresh this table
            self.setMessage(self._currentMessage, True)
            
            JOptionPane.showMessageDialog(self.panel, "Mapping updated for " + tagName)

    def getMessage(self):
        return self._currentMessage
    
    def isModified(self):
        return False
    
    def getSelectedData(self):
        return None
