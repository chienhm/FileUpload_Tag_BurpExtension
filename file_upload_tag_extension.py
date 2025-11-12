# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, IMessageEditorTabFactory, IMessageEditorTab
from javax.swing import (JPanel, JButton, JTextArea, JScrollPane, JFileChooser, JOptionPane, BorderFactory)
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout, Dimension, Color, Font
from java.io import FileInputStream, File as JFile
import re

class BurpExtender(IBurpExtender, IHttpListener, IMessageEditorTabFactory):
    
    # Storage for file mappings
    file_mappings = {}
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("File Upload Tag")
        
        # Don't add main tab - only use the File Tags tab in Repeater
        # self.initGUI()
        # callbacks.addSuiteTab(self)
        
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
            typefilePattern = r'<@(typefile\d*)@>'
            typefileMatches = list(re.finditer(typefilePattern, requestStr))
            
            if len(matches) == 0:
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
            
            # Now replace ALL typefile tags in the updated request
            # If same typefile tag appears multiple times, all get same Content-Type
            # E.g., multiple <@typefile@> all get Content-Type from getfile@
            requestStr = self._helpers.bytesToString(newRequest)
            
            # Build a mapping of typefile tags to Content-Type
            typefileMapping = {}
            for info in getfileInfos:
                typefileTag = "<@typefile" + info['paramName'].replace("getfile", "") + "@>"
                contentType = self.getContentType(info['filePath'])
                typefileMapping[typefileTag] = contentType
                print("[DEBUG] Mapping: " + typefileTag + " -> " + contentType)
            
            # Replace all occurrences of each typefile tag
            for typefileTag, contentType in typefileMapping.items():
                # Replace ALL occurrences of this tag (not just first)
                while typefileTag in requestStr:
                    print("[DEBUG] Replacing " + typefileTag + " with " + contentType)
                    contentTypeBytes = self._helpers.stringToBytes(contentType)
                    newRequest = self.replaceInRequest(newRequest, typefileTag, contentTypeBytes)
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


class FileUploadTagEditorTab(IMessageEditorTab):
    """Custom editor tab to show which tags will be replaced"""
    
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._controller = controller
        self._editable = editable
        self._currentMessage = None
        self._currentParams = []
        
        # Create UI
        self.panel = JPanel(BorderLayout())
        
        # Text area for info
        self._txtInput = extender._callbacks.createTextEditor()
        self.panel.add(self._txtInput.getComponent(), BorderLayout.CENTER)
        
        # Bottom panel for buttons
        self.buttonPanel = JPanel()
        self.buttonPanel.setBorder(EmptyBorder(5, 5, 5, 5))
        
        self.selectFileButton = JButton("Select File", actionPerformed=self.reloadFile)
        self.selectFileButton.setEnabled(False)
        self.selectFileButton.setPreferredSize(Dimension(200, 40))
        self.selectFileButton.setFont(Font("Dialog", Font.BOLD, 14))
        self.buttonPanel.add(self.selectFileButton)
        
        self.panel.add(self.buttonPanel, BorderLayout.SOUTH)
        
    def reloadFile(self, event):
        """Allow user to select a new file for a parameter"""
        if not self._currentParams:
            JOptionPane.showMessageDialog(self.panel, 
                "No file tags detected in current request!", 
                "No Tags", 
                JOptionPane.WARNING_MESSAGE)
            return
        
        # If multiple parameters, let user choose which one to update
        if len(self._currentParams) > 1:
            # Create a selection dialog
            paramArray = [p for p in self._currentParams]
            selectedParam = JOptionPane.showInputDialog(
                self.panel,
                "Select parameter to assign/update file:",
                "Choose Parameter",
                JOptionPane.QUESTION_MESSAGE,
                None,
                paramArray,
                paramArray[0]
            )
            if not selectedParam:
                return
            paramName = str(selectedParam)
        else:
            paramName = self._currentParams[0]
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Select file for parameter: " + paramName)
        
        # Set initial directory if mapping exists
        if paramName in BurpExtender.file_mappings:
            currentFile = JFile(BurpExtender.file_mappings[paramName])
            if currentFile.exists():
                chooser.setCurrentDirectory(currentFile.getParentFile())
                chooser.setSelectedFile(currentFile)
        
        ret = chooser.showOpenDialog(self.panel)
        if ret == JFileChooser.APPROVE_OPTION:
            newFile = chooser.getSelectedFile()
            newPath = newFile.getAbsolutePath()
            
            # Update mapping
            oldPath = BurpExtender.file_mappings.get(paramName, "None")
            BurpExtender.file_mappings[paramName] = newPath
            
            # Refresh display
            self.setMessage(self._currentMessage, True)
            
            JOptionPane.showMessageDialog(self.panel, 
                "File Selected Successfully!\n\n" +
                "Parameter: " + paramName + "\n" +
                "File: " + newFile.getName() + "\n" +
                "Size: " + self.formatBytes(newFile.length()) + "\n\n" +
                "The tag <@" + paramName + "@> will be replaced with this file\n" +
                "when you send the request.", 
                "Success", 
                JOptionPane.INFORMATION_MESSAGE)
    
    def getTabCaption(self):
        return "File Tags"
    
    def getUiComponent(self):
        return self.panel
    
    def isEnabled(self, content, isRequest):
        if not isRequest:
            return False
        
        # Check if content contains any file upload tags (getfile pattern only)
        contentStr = self._extender._helpers.bytesToString(content)
        pattern = r'<@(getfile\d*)(?::([^@]+))?@>'
        typefilePattern = r'<@(typefile\d*)@>'
        return re.search(pattern, contentStr) is not None or re.search(typefilePattern, contentStr) is not None
    
    def setMessage(self, content, isRequest):
        self._currentMessage = content
        self._currentParams = []
        
        if content is None:
            self._txtInput.setText(None)
            self.selectFileButton.setEnabled(False)
            return
        
        # Highlight tags in the message
        contentStr = self._extender._helpers.bytesToString(content)
        pattern = r'<@(getfile\d*)(?::([^@]+))?@>'
        typefilePattern = r'<@(typefile\d*)@>'
        
        infoText = "=" * 70 + "\n"
        infoText += "   FILE UPLOAD TAGS DETECTED\n"
        infoText += "=" * 70 + "\n\n"
        matches = re.finditer(pattern, contentStr)
        
        # Also detect typefile tags
        typefileMatches = list(re.finditer(typefilePattern, contentStr))
        typefileParams = {}
        for match in typefileMatches:
            typefileParam = match.group(1)
            typefileParams[typefileParam] = match.group(0)
        
        foundTags = 0
        for match in matches:
            foundTags += 1
            foundTags = True
            paramName = match.group(1)
            encoding = match.group(2) if match.group(2) else "raw"
            tag = match.group(0)
            
            # Add to current params list
            if paramName not in self._currentParams:
                self._currentParams.append(paramName)
            
                if paramName in BurpExtender.file_mappings:
                    filePath = BurpExtender.file_mappings[paramName]
                    jfile = JFile(filePath)
                    fileSize = jfile.length() if jfile.exists() else 0
                    fileExists = jfile.exists()
                    
                    # Check if there's a corresponding typefile tag
                    typefileParam = "typefile" + paramName.replace("getfile", "")
                    hasTypefileTag = typefileParam in typefileParams
                    
                    infoText += "[" + str(foundTags) + "] Tag: " + tag + "\n"
                    infoText += "    " + "-" * 60 + "\n"
                    infoText += "    Parameter : " + paramName + "\n"
                    infoText += "    File Path : " + filePath + "\n"
                    
                    if fileExists:
                        infoText += "    File Size : " + self.formatBytes(fileSize) + "\n"
                        contentType = self._extender.getContentType(filePath)
                        infoText += "    Content-Type : " + contentType + "\n"
                        if hasTypefileTag:
                            infoText += "    Type Tag  : " + typefileParams[typefileParam] + " (will auto-replace)\n"
                        infoText += "    Status    : READY (file exists)\n"
                    else:
                        infoText += "    File Size : N/A\n"
                        infoText += "    Status    : WARNING - File not found!\n"
                    
                    infoText += "    Encoding  : " + encoding + "\n"
                    infoText += "\n"
                else:
                    # Check if there's a corresponding typefile tag
                    typefileParam = "typefile" + paramName.replace("getfile", "")
                    hasTypefileTag = typefileParam in typefileParams
                    
                    infoText += "[" + str(foundTags) + "] Tag: " + tag + "\n"
                    infoText += "    " + "-" * 60 + "\n"
                    infoText += "    Parameter : " + paramName + "\n"
                    if hasTypefileTag:
                        infoText += "    Type Tag  : " + typefileParams[typefileParam] + " (will auto-fill)\n"
                    infoText += "    Status    : NOT CONFIGURED - Click button below to select file\n"
                    infoText += "    Encoding  : " + encoding + "\n"
                    infoText += "\n"
        
        if foundTags == 0:
            infoText = "=" * 70 + "\n"
            infoText += "   FILE UPLOAD TAG - NO TAGS DETECTED\n"
            infoText += "=" * 70 + "\n\n"
            infoText += "How to use:\n\n"
            infoText += "  1. Add a tag to your request body:\n\n"
            infoText += "     Examples:\n"
            infoText += "       <@getfile@>          - Upload file as raw binary\n"
            infoText += "       <@getfile1@>         - Upload second file as raw binary\n"
            infoText += "       <@getfile:base64@>   - Upload file encoded in base64\n"
            infoText += "       <@getfile2:base64@>  - Upload third file encoded in base64\n\n"
            infoText += "     Content-Type auto-detection:\n"
            infoText += "       <@typefile@>         - Auto-fill Content-Type for getfile\n"
            infoText += "       <@typefile1@>        - Auto-fill Content-Type for getfile1\n"
            infoText += "       <@typefile2@>        - Auto-fill Content-Type for getfile2\n\n"
            infoText += "  2. This tab will automatically detect your tag\n\n"
            infoText += "  3. Click 'Select File' button that appears below\n\n"
            infoText += "  4. Choose your file from computer\n\n"
            infoText += "  5. Send request - tag will be replaced with actual file content\n\n"
            infoText += "=" * 70 + "\n"
            infoText += "Note: Only tags starting with 'getfile' are supported\n"
            infoText += "      (getfile, getfile1, getfile2, getfile3, etc.)\n"
            infoText += "=" * 70 + "\n"
            self.selectFileButton.setEnabled(False)
        else:
            infoText += "\n" + "=" * 70 + "\n"
            infoText += "   ACTIONS\n"
            infoText += "=" * 70 + "\n\n"
            
            # Count how many need file selection
            needSelection = 0
            for param in self._currentParams:
                if param not in BurpExtender.file_mappings:
                    needSelection += 1
            
            if needSelection > 0:
                infoText += ">>> " + str(needSelection) + " tag(s) need file selection <<<\n\n"
            
            infoText += "Click the button below to select/change file for any tag.\n"
            infoText += "After selecting file, send your request to upload.\n\n"
            infoText += "=" * 70 + "\n\n\n"
            
            # Add Content-Type mapping reference
            infoText += "=" * 70 + "\n"
            infoText += "  CONTENT-TYPE MAPPING REFERENCE\n"
            infoText += "=" * 70 + "\n\n"
            
            infoText += "PHP Extensions:\n"
            infoText += "  .php, .php2-7, .phps, .pht, .phtml -> application/x-httpd-php\n"
            infoText += "  .inc, .htaccess -> text/plain\n\n"
            
            infoText += "ASP Extensions:\n"
            infoText += "  .asp, .aspx, .aspq -> text/asp\n"
            infoText += "  .ashx, .asmx, .asa -> text/plain\n"
            infoText += "  .config -> application/xml\n\n"
            
            infoText += "JSP Extensions:\n"
            infoText += "  .jsp, .jspx, .jsw, .jsv, .jspf -> text/html\n"
            infoText += "  .do, .action -> text/html\n\n"
            
            infoText += "Script Extensions:\n"
            infoText += "  .py, .py3, .pyw -> text/x-python\n"
            infoText += "  .sh -> application/x-sh\n"
            infoText += "  .bat -> application/x-bat\n"
            infoText += "  .ps1 -> text/plain\n\n"
            
            infoText += "Document Extensions:\n"
            infoText += "  .pdf -> application/pdf\n"
            infoText += "  .doc -> application/msword\n"
            infoText += "  .docx -> application/vnd.openxmlformats-officedocument.wordprocessingml.document\n"
            infoText += "  .xls -> application/vnd.ms-excel\n"
            infoText += "  .xlsx -> application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\n"
            infoText += "  .txt -> text/plain\n"
            infoText += "  .csv -> text/csv\n"
            infoText += "  .json -> application/json\n"
            infoText += "  .xml -> application/xml\n\n"
            
            infoText += "Image Extensions:\n"
            infoText += "  .jpg, .jpeg -> image/jpeg\n"
            infoText += "  .png -> image/png\n"
            infoText += "  .gif -> image/gif\n"
            infoText += "  .bmp -> image/bmp\n"
            infoText += "  .svg -> image/svg+xml\n"
            infoText += "  .ico -> image/x-icon\n"
            infoText += "  .tif, .tiff -> image/tiff\n\n"
            
            infoText += "Audio Extensions:\n"
            infoText += "  .mp3 -> audio/mpeg\n"
            infoText += "  .wav -> audio/wav\n"
            infoText += "  .aac -> audio/aac\n"
            infoText += "  .flac -> audio/flac\n"
            infoText += "  .ogg -> audio/ogg\n"
            infoText += "  .m4a -> audio/mp4\n\n"
            
            infoText += "Video Extensions:\n"
            infoText += "  .mp4 -> video/mp4\n"
            infoText += "  .avi -> video/x-msvideo\n"
            infoText += "  .mkv -> video/x-matroska\n"
            infoText += "  .mov -> video/quicktime\n"
            infoText += "  .wmv -> video/x-ms-wmv\n"
            infoText += "  .flv -> video/x-flv\n"
            infoText += "  .webm -> video/webm\n"
            infoText += "  .mpeg, .mpg -> video/mpeg\n\n"
            
            infoText += "Archive Extensions:\n"
            infoText += "  .zip -> application/zip\n"
            infoText += "  .rar -> application/x-rar-compressed\n"
            infoText += "  .tar -> application/x-tar\n"
            infoText += "  .gz -> application/gzip\n"
            infoText += "  .7z -> application/x-7z-compressed\n"
            infoText += "  .jar -> application/java-archive\n\n"
            
            infoText += "Executable Extensions:\n"
            infoText += "  .exe -> application/x-msdownload\n"
            infoText += "  .dll -> application/x-msdownload\n"
            infoText += "  .msi -> application/x-msi\n\n"
            
            infoText += "Other Extensions:\n"
            infoText += "  .swf -> application/x-shockwave-flash\n"
            infoText += "  .bin -> application/octet-stream\n"
            infoText += "  (unknown) -> application/octet-stream\n\n"
            infoText += "=" * 70 + "\n"
            
            self.selectFileButton.setEnabled(True)
        
        self._txtInput.setText(self._extender._helpers.stringToBytes(infoText))
    
    def formatBytes(self, size):
        """Format file size in human readable format"""
        if size < 1024:
            return str(size) + " bytes"
        elif size < 1024 * 1024:
            return str(round(size / 1024.0, 2)) + " KB"
        elif size < 1024 * 1024 * 1024:
            return str(round(size / (1024.0 * 1024), 2)) + " MB"
        else:
            return str(round(size / (1024.0 * 1024 * 1024), 2)) + " GB"
    
    def getMessage(self):
        return self._txtInput.getText()
    
    def isModified(self):
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        return self._txtInput.getSelectedText()
