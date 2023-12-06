# Hướng dẫn sử dụng công cụ kiểm thử và quản lý lỗ hổng 

Bước 1 : cài đặt thư viện Python thông qua câu lệnh pip
```php

pip install -r requirements.txt

```
Bước 2 : Cài đặt OWASP ZAP Proxy theo đường dẫn [OWASP ZAP](https://www.zaproxy.org/download/)

Bước 3 : Sau khi cài đặt OWASP ZAP theo như hướng dẫn, truy cập để lấy API qua đường dẫn

`Màn hình ZAP -> Tools -> Options -> API -> Generate API`

Bước 4 : Truy cập file Grrrrr/src/security.py thay đổi giá trị API_KEY bằng giá trị vừa khởi tạo, đồng thời cập nhật địa chỉ proxy của ZAP( mặc định là localhost:8080)

Bước 5 : Khởi động công cụ bằng chạy lệnh 
```
python3 app.py
```
hoặc 
```
python.exe app.py
```