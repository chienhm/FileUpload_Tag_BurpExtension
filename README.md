# File Upload Tag Extension for Burp Suite

Extension Burp Suite cho phép upload file thông qua custom tags trong Repeater và Intruder. Extension tự động thay thế tags bằng nội dung file thực từ máy tính, hỗ trợ mã hóa base64 và tự động nhận diện Content-Type.

---

## 🎯 Tính năng

### 1. **File Upload Tags**
Upload file từ máy tính sử dụng tags đơn giản trong request:

```
<@getfile@>     - Upload file đầu tiên (raw binary)
<@getfile1@>    - Upload file thứ hai (raw binary)
<@getfile2@>    - Upload file thứ ba (raw binary)
<@getfileN@>    - Upload file thứ N (N = bất kỳ số nào)
```

### 2. **Base64 Encoding**
Tự động mã hóa file thành base64 bằng cách thêm modifier `:base64`:

```
<@getfile:base64@>      - Upload file được mã hóa base64
<@getfile1:base64@>     - Upload file thứ hai mã hóa base64
<@getfile2:base64@>     - Upload file thứ ba mã hóa base64
```

### 3. **Auto Content-Type Detection**
Tự động nhận diện và điền Content-Type header dựa trên file extension:

```
<@typefile@>    - Auto-detect Content-Type cho getfile
<@typefile1@>   - Auto-detect Content-Type cho getfile1
<@typefile2@>   - Auto-detect Content-Type cho getfile2
```

**Hỗ trợ 130+ định dạng file:**
- **Web**: PHP, ASP, JSP, ColdFusion, HTML, JS, XML
- **Scripts**: Python, Perl, Bash, PowerShell
- **Documents**: PDF, Word, Excel, CSV, JSON, TXT
- **Images**: JPG, PNG, GIF, BMP, SVG, TIFF, RAW, ICO
- **Audio**: MP3, WAV, AAC, FLAC, OGG, M4A, WMA
- **Video**: MP4, AVI, MKV, MOV, WMV, FLV, WEBM, MPEG
- **Archives**: ZIP, RAR, TAR, GZ, 7Z, JAR

### 4. **Automatic Content-Length Update**
Extension tự động tính toán lại và cập nhật Content-Length header sau khi thay thế tags bằng nội dung file.

---

## 📦 Cài đặt

### Bước 1: Tải Extension

Download file `file_upload_tag_extension.py` về máy.

### Bước 2: Load vào Burp Suite

1. Mở **Burp Suite**
2. Vào tab **Extender** → **Extensions**
3. Click button **Add**
4. Trong dialog:
   - **Extension Type**: Chọn **Python**
   - **Extension File**: Browse và chọn file `file_upload_tag_extension.py`
5. Click **Next**

### Bước 3: Xác nhận đã load thành công

- Kiểm tra tab **Output** trong Extender, sẽ thấy thông báo:
  ```
  File Upload Tag Extension Loaded!
  ```
- Khi mở request trong **Repeater**, sẽ thấy tab mới **"File Tags"** xuất hiện

---

## 🚀 Hướng dẫn sử dụng

### Ví dụ 1: Upload File Multipart/Form-Data

**Bước 1:** Tạo request trong Repeater với tags:

```http
POST /upload HTTP/1.1
Host: example.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary123
Content-Length: 1234

------WebKitFormBoundary123
Content-Disposition: form-data; name="file"; filename="document.xlsx"
Content-Type: <@typefile@>

<@getfile@>
------WebKitFormBoundary123--
```

**Bước 2:** Chuyển sang tab **"File Tags"** trong request editor

**Bước 3:** Click button **"Select File"** và chọn file từ máy tính

**Bước 4:** Send request - tags sẽ tự động được thay thế:
- `<@getfile@>` → Nội dung binary của file
- `<@typefile@>` → `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`

---

### Ví dụ 2: Upload File Base64 (JSON API)

```http
POST /api/upload HTTP/1.1
Host: api.example.com
Content-Type: application/json

{
  "filename": "document.pdf",
  "contentType": "<@typefile@>",
  "content": "<@getfile:base64@>"
}
```

Sau khi chọn file PDF:
- `<@getfile:base64@>` → File được mã hóa base64
- `<@typefile@>` → `application/pdf`

---

### Ví dụ 3: Upload Nhiều File

```http
POST /upload-multiple HTTP/1.1
Host: example.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary123

------WebKitFormBoundary123
Content-Disposition: form-data; name="file1"; filename="doc1.pdf"
Content-Type: <@typefile@>

<@getfile@>
------WebKitFormBoundary123
Content-Disposition: form-data; name="file2"; filename="doc2.xlsx"
Content-Type: <@typefile1@>

<@getfile1@>
------WebKitFormBoundary123
Content-Disposition: form-data; name="image"; filename="logo.png"
Content-Type: <@typefile2@>

<@getfile2@>
------WebKitFormBoundary123--
```

Extension sẽ hiển thị 3 tags riêng biệt, cho phép chọn 3 file khác nhau cho mỗi tag.

---

## 📋 Tab "File Tags" trong Repeater

Khi mở request chứa tags trong Repeater, tab **"File Tags"** sẽ hiển thị:

```
==================================================================
  FILE UPLOAD TAGS DETECTED
==================================================================

[True] Tag: <@getfile@>
--------------------------------------------------------------------
  Parameter   : getfile
  File Path   : /home/user/Desktop/document.xlsx
  File Size   : 6.97 KB
  Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
  Type Tag    : <@typefile@> (will auto-replace)
  Status      : READY (file exists)
  Encoding    : raw

==================================================================
  ACTIONS
==================================================================

Click the button below to select/change file for any tag.
After selecting file, send your request to upload.
```

### Thông tin hiển thị:

- **Parameter**: Tên tag (getfile, getfile1, getfile2, ...)
- **File Path**: Đường dẫn file đã chọn
- **File Size**: Kích thước file (tự động format: bytes, KB, MB, GB)
- **Content-Type**: MIME type được auto-detect
- **Type Tag**: Tag typefile tương ứng (nếu có)
- **Status**: READY (file tồn tại) hoặc NOT SELECTED
- **Encoding**: raw hoặc base64

---

## 📝 Content-Type Mapping Reference

Extension tự động nhận diện Content-Type dựa trên file extension:

### PHP Extensions
```
.php, .php2, .php3, .php4, .php5, .php6, .php7 → application/x-httpd-php
.phps → application/x-httpd-php-source
.pht, .phtml → text/html
.inc, .htaccess → text/plain
.phar → application/octet-stream
```

### ASP Extensions
```
.asp, .aspx, .aspq → text/asp
.ashx, .asmx, .asa → text/plain
.config → application/xml
.soap → application/soap+xml
.cshtm, .cshtml, .vbhtm, .vbhtml → text/html
.cer → application/x-x509-ca-cert
```

### JSP Extensions
```
.jsp, .jspx, .jsw, .jsv, .jspf → text/html
.do, .action → text/html
```

### ColdFusion Extensions
```
.cfm, .cfml, .cfc, .dbm → text/html
```

### Script Extensions
```
.py, .py3, .pyw, .pyx, .pyi → text/x-python
.pyc, .pyo → application/x-python-code
.sh → application/x-sh
.bat → application/x-bat
.ps1, .psd1, .psm1 → text/plain
.pl → text/x-perl
.cgi → text/plain
```

### Document Extensions
```
.pdf → application/pdf
.doc → application/msword
.docx → application/vnd.openxmlformats-officedocument.wordprocessingml.document
.xls → application/vnd.ms-excel
.xlsx → application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
.txt → text/plain
.csv → text/csv
.json → application/json
.xml → application/xml
```

### Image Extensions
```
.jpg, .jpeg → image/jpeg
.png → image/png
.gif → image/gif
.bmp → image/bmp
.svg → image/svg+xml
.ico → image/x-icon
.tif, .tiff → image/tiff
.raw, .cr2, .nef, .orf, .sr2 → image/x-raw (camera RAW formats)
.eps → application/postscript
```

### Audio Extensions
```
.mp3 → audio/mpeg
.wav → audio/wav
.aac → audio/aac
.flac → audio/flac
.ogg, .oga → audio/ogg
.m4a → audio/mp4
.wma → audio/x-ms-wma
.opus → audio/opus
.weba → audio/webm
.mid, .midi → audio/midi
```

### Video Extensions
```
.mp4 → video/mp4
.avi → video/x-msvideo
.mkv → video/x-matroska
.mov → video/quicktime
.wmv → video/x-ms-wmv
.flv → video/x-flv
.webm → video/webm
.mpeg, .mpg → video/mpeg
.m4v → video/x-m4v
.3gp → video/3gpp
.3g2 → video/3gpp2
.ogv → video/ogg
.ts → video/mp2t
.vob → video/dvd
.rm → application/vnd.rn-realmedia
.rmvb → application/vnd.rn-realmedia-vbr
.asf → video/x-ms-asf
```

### Archive Extensions
```
.zip → application/zip
.rar → application/x-rar-compressed
.tar → application/x-tar
.gz → application/gzip
.7z → application/x-7z-compressed
.jar → application/java-archive
```

### Executable Extensions
```
.exe, .dll → application/x-msdownload
.msi → application/x-msi
.bin → application/octet-stream
```

### Other Extensions
```
.swf → application/x-shockwave-flash
.html, .htm → text/html
.js → application/javascript
.yaws → text/html (Erlang)
(unknown) → application/octet-stream
```

---

## 🔧 Quy tắc đặt tên Tags

### File Upload Tags
- Pattern: `<@getfile[N][:base64]@>`
- Số `N` có thể bỏ qua cho file đầu tiên: `<@getfile@>` = `<@getfile0@>`
- Thêm `:base64` để mã hóa: `<@getfile:base64@>`

**Ví dụ hợp lệ:**
```
<@getfile@>
<@getfile1@>
<@getfile2@>
<@getfile10@>
<@getfile:base64@>
<@getfile1:base64@>
```

### Content-Type Tags
- Pattern: `<@typefile[N]@>`
- Số `N` phải khớp với số trong tag `getfile` tương ứng

**Mapping:**
```
<@getfile@>   ↔ <@typefile@>
<@getfile1@>  ↔ <@typefile1@>
<@getfile2@>  ↔ <@typefile2@>
```

---

## ⚙️ Cách hoạt động

1. **Tag Detection**: Extension quét request tìm tags `<@getfile*@>` và `<@typefile*@>`
2. **File Selection**: Người dùng chọn file từ máy tính qua GUI
3. **File Reading**: File được đọc dạng binary sử dụng Java FileInputStream
4. **Encoding**: Nếu có modifier `:base64`, nội dung file được mã hóa
5. **Type Detection**: Nếu có tag `<@typefile@>`, Content-Type được auto-detect từ extension
6. **Tag Replacement**: Tags được thay thế bằng nội dung file hoặc Content-Type
7. **Content-Length Update**: Content-Length header tự động được tính toán lại
8. **Request Sending**: Request đã sửa đổi được gửi tới server

---

## 🛠️ Chi tiết kỹ thuật

- **Ngôn ngữ**: Python (Jython 2.7)
- **Burp API**: Implement `IHttpListener` và `IMessageEditorTabFactory`
- **File Handling**: Sử dụng Java FileInputStream để đọc binary file chính xác
- **Byte Conversion**: Xử lý Java signed bytes (-128 to 127) một cách chính xác
- **Encoding**: Sử dụng ISO-8859-1 để bảo toàn tính toàn vẹn của binary data
- **Base64**: Sử dụng thư viện base64 của Python

---

## ❗ Xử lý sự cố

### Extension không load được

**Nguyên nhân:**
- Burp Suite chưa cài đặt Jython
- Đường dẫn Jython không đúng

**Giải pháp:**
1. Vào **Extender** → **Options** → **Python Environment**
2. Download Jython Standalone JAR từ https://www.jython.org/download
3. Chọn đường dẫn tới file `jython-standalone-*.jar`
4. Reload extension

---

## 💡 Use Cases

### 1. Web Security Testing
- Test file upload vulnerabilities (unrestricted file upload, XXE, etc.)
- Bypass file type restrictions
- Upload malicious files (webshells, malware, etc.)
- Test file size limitations
- Test filename sanitization

### 2. API Testing
- Upload files tới REST APIs
- Test base64 encoded file uploads
- Test multiple file uploads trong single request
- Validate Content-Type handling
- Test chunked upload

### 3. Penetration Testing
- Upload reverse shells (PHP, ASP, JSP, Python, etc.)
- Test file inclusion vulnerabilities
- Exploit XXE với malicious XML/SVG files
- Test archive file handling (ZIP bombs, path traversal)
- Bypass WAF/security filters

---

## 📖 Ví dụ thực tế

### Ví dụ 1: Upload PHP Webshell

```http
POST /upload.php HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary123

------WebKitFormBoundary123
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: <@typefile@>

<@getfile@>
------WebKitFormBoundary123--
```

**Kết quả:**
- Chọn file `shell.php`
- Extension detect `.php` → Set `Content-Type: application/x-httpd-php`
- Tag `<@getfile@>` được thay bằng code PHP shell

---

### Ví dụ 2: Upload Malicious SVG (XXE Attack)

```http
POST /avatar/upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary123

------WebKitFormBoundary123
Content-Disposition: form-data; name="avatar"; filename="profile.svg"
Content-Type: <@typefile@>

<@getfile@>
------WebKitFormBoundary123--
```

**Kết quả:**
- Chọn file SVG chứa XXE payload
- Extension set `Content-Type: image/svg+xml`
- Server xử lý file SVG → trigger XXE vulnerability

---

### Ví dụ 3: API Upload với Base64

```http
POST /api/v1/documents HTTP/1.1
Host: api.target.com
Content-Type: application/json

{
  "document": {
    "name": "invoice.pdf",
    "type": "<@typefile@>",
    "data": "<@getfile:base64@>"
  }
}
```

**Kết quả:**
- Chọn file PDF
- `<@getfile:base64@>` → File được encode base64
- `<@typefile@>` → `application/pdf`
- JSON valid và server nhận được file đúng format

---

### Ví dụ 4: Upload Multiple Files

```http
POST /api/documents/batch HTTP/1.1
Host: api.target.com
Content-Type: application/json

{
  "files": [
    {
      "name": "report.pdf",
      "type": "<@typefile@>",
      "content": "<@getfile:base64@>"
    },
    {
      "name": "data.xlsx",
      "type": "<@typefile1@>",
      "content": "<@getfile1:base64@>"
    },
    {
      "name": "image.png",
      "type": "<@typefile2@>",
      "content": "<@getfile2:base64@>"
    }
  ]
}
```

**Kết quả:**
- Extension hiển thị 3 tags riêng biệt
- Chọn 3 files khác nhau
- Tất cả được encode base64 và Content-Type tự động điền

---

## 📜 License

Free to use for security testing and penetration testing purposes.

---

**Happy Testing! 🚀**
