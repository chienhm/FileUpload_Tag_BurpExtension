# File Upload Tag Extension for Burp Suite

**🎨 Version 2.1 - Enhanced Repeater Integration!**

Extension cho phép upload file thông qua custom tags trong Repeater và Intruder. Extension tự động thay thế tags bằng nội dung file thực từ máy tính, hỗ trợ mã hóa base64, tự động nhận diện Content-Type và hỗ trợ giả lập Content-Type tùy chỉnh.

---

## 🆕 What's New in v2.1

### Giao diện & Tính năng mới!

- ✅ **Streamlined UI**: Tích hợp hoàn toàn vào tab **"File Tags"** trong Repeater/Intruder (đã loại bỏ tab Global thừa thãi).
- ✅ **Smart Reference**: Bảng tham chiếu Content-Type đầy đủ, có thể kéo thả (Resizable Split Pane).
- ✅ **Explicit Content-Type**: Hỗ trợ tag mới `<@typefile:ext@>` để giả lập Content-Type mà không cần file thực.
- ✅ **Fallback Handling**: Tự động xử lý các extension lạ về `application/octet-stream`.
- ✅ **Dependency Check**: Cảnh báo lỗi nếu dùng tag tự động `<@typefile@>` mà thiếu `<@getfile@>`.

---

## 🎯 Tính năng

### 1. **File Upload Tags**
Upload file từ máy tính sử dụng tags đơn giản trong request:

```
<@getfile@>     - Upload file đầu tiên (raw binary)
<@getfile1@>    - Upload file thứ hai (raw binary)
<@getfileN@>    - Upload file thứ N (N = bất kỳ số nào)
```

### 2. **Base64 Encoding**
Tự động mã hóa file thành base64 bằng cách thêm modifier `:base64`:

```
<@getfile:base64@>      - Upload file được mã hóa base64
<@getfile1:base64@>     - Upload file thứ hai mã hóa base64
```

### 3. **Content-Type Detection & Simulation**

**Cách 1: Tự động theo file (Dynamic)**
Tự động nhận diện Content-Type dựa trên file bạn chọn cho tag `<@getfile@>` tương ứng:
```
<@typefile@>    - Auto-detect Content-Type cho file của <@getfile@>
<@typefile1@>   - Auto-detect Content-Type cho file của <@getfile1@>
```

**Cách 2: Chỉ định cứng (Static) - NEW!**
Giả lập Content-Type của một định dạng cụ thể mà không cần upload file đó. Rất hữu ích khi bạn chỉ muốn thay đổi header `Content-Type`.
```
<@typefile:php@>      -> application/x-httpd-php
<@typefile:jpg@>      -> image/jpeg
<@typefile:extxml@>  -> application/octet-stream (nếu không có trong list hỗ trợ)
```

### 4. **Automatic Content-Length Update**
Extension tự động tính toán lại và cập nhật Content-Length header sau khi thay thế tags.

---

## 📦 Cài đặt

1. **Tải Extension**: Download file `file_upload_tag_extension.py`.
2. **Cài đặt Jython**: Đảm bảo Burp Suite đã được cấu hình với Jython Standalone JAR (Extender -> Options -> Python Environment).
3. **Load Extension**:
   - Vào tab **Extender** → **Extensions**.
   - Click **Add**.
   - Chọn **Extension Type: Python**.
   - Chọn file `file_upload_tag_extension.py`.
4. **Sử dụng**: Mở Repeater, bạn sẽ thấy tab **"File Tags"** xuất hiện bên cạnh tab Request khi bạn chèn các tags.

---

## 🚀 Hướng dẫn sử dụng

### Bước 1: Chèn Tags vào Request
Trong tab **Repeater** hoặc **Intruder**, thay thế nội dung file hoặc Content-Type bằng các tags.

**Ví dụ Multipart Upload:**
```http
POST /upload HTTP/1.1
...
Content-Type: multipart/form-data; boundary=----Boundary123

------Boundary123
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: <@typefile@>

<@getfile@>
------Boundary123--
```

**Ví dụ JSON Upload (Base64):**
```json
{
  "file": "<@getfile:base64@>",
  "type": "<@typefile:pdf@>"
}
```

### Bước 2: Cấu hình trong tab "File Tags"
1. Chuyển sang tab **"File Tags"** (nằm cạnh tab Raw, Hex...).
2. Bạn sẽ thấy danh sách các tags được phát hiện trong request.
3. **Chọn file**:
   - **Cách 1**: Double-click vào dòng chứa tag `<@getfile...>` để mở hộp thoại chọn file nhanh.
   - **Cách 2**: Chọn dòng chứa tag `<@getfile...>` rồi nhấn nút **"Select/Change File"** ở dưới cùng.
   - *Lưu ý*: Các dòng `<@typefile...>` là chỉ đọc (read-only) và không thể chọn file.
4. **Kiểm tra**:
   - Status chuyển sang **"Ready"**.
   - Cột Content-Type hiển thị loại file được nhận diện.
   - Nếu dùng `<@typefile:ext@>`, nó sẽ luôn hiện **"Ready"** và Content-Type tương ứng.

### Bước 3: Gửi Request
Quay lại tab **Raw** (hoặc cứ để ở File Tags) và nhấn **Send**. Extension sẽ tự động thay thế tags bằng dữ liệu thực trước khi gửi đi.

---

## 📋 Bảng tham chiếu Content-Type (Hỗ trợ 130+)

Extension tích hợp sẵn bảng tham chiếu ngay trong giao diện (phần dưới của tab File Tags). Một số định dạng phổ biến:

- **Web**: `.php` (application/x-httpd-php), `.html` (text/html), `.js` (application/javascript)
- **Scripts**: `.py`, `.pl`, `.sh`, `.bat`, `.ps1`
- **Documents**: `.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx`
- **Images**: `.jpg`, `.png`, `.gif`, `.svg`, `.bmp`
- **Archives**: `.zip`, `.rar`, `.tar.gz`
- **Executables**: `.exe`, `.dll`, `.msi`

*Nếu extension lạ không có trong danh sách, mặc định sẽ là `application/octet-stream`.*

---

## 🔧 Quy tắc Tags

| Tag | Mô tả | Ví dụ |
|-----|-------|-------|
| `<@getfile@>` | File binary mặc định (index 0) | Upload file chính |
| `<@getfileN@>` | File binary thứ N | `<@getfile1@>`, `<@getfile2@>` |
| `<@getfile:base64@>` | File mặc định mã hóa Base64 | Upload ảnh trong JSON |
| `<@typefile@>` | Content-Type của file mặc định | Đi theo `<@getfile@>` |
| `<@typefileN@>` | Content-Type của file thứ N | Đi theo `<@getfileN@>` |
| `<@typefile:ext@>` | Content-Type cố định theo đuôi | `<@typefile:php@>`, `<@typefile:png@>` |

---

## 💡 Use Cases

1.  **Webshell Upload**: Dễ dàng thử nghiệm upload các loại webshell (.php, .jsp, .asp) mà không cần sửa đổi file gốc liên tục.
2.  **Bypass File Type Checks**: Sử dụng `<@typefile:jpg@>` để giả mạo Content-Type là ảnh trong khi gửi nội dung là file script `<@getfile@>`.
3.  **Polyglot / Magic Bytes**: Upload file có nội dung binary phức tạp mà không bị lỗi encoding khi copy-paste trong Burp.
4.  **API Testing**: Test upload file qua JSON/XML với base64 encoding một cách nhanh chóng.

---

**Happy Hacking! 🚀**
