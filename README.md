Chức năng:

Không tự ý BAN IP quốc gia VN khi đăng nhập sai

Tự detect được quốc gia của đối tượng đăng nhập sai

Tránh trùng lặp ACCEPT và DROP source IP đã thao tác.

Tự động pull log từ mailserver về để phân tích

Remote thông qua SSH để thêm rule vào firewall

Alert mỗi khi có người bị BAN hoặc IP VN đang tấn công.

Có thể thêm whitelist IP hoặc quốc gia vào tool

Có thể phân tích log từ xưa đến nay cùng 1 lúc (cẩn thận)


Cơ chế hoạt động:

Tool PHP cli (test trên php 7.4) kết hợp bash shell ubuntu.

Có sử dụng gói whois (apt install whois).

Cài đặt trên máy tính cá nhân, có quyền truy cập vào mailserver bằng SSH key

Script trên máy tính cá nhân sẽ SSH đến mailserver và pull zimbra.log về path mặc định /var/log/zimbra.log (không cần quyền sudo).

Sau khi pull log về, bashshell phân tích log thành table có dạng

Ha Tang Van Hanh > Chống brute attack mail server > image2021-8-27_16-40-46.png

Xử lý từng IP vượt qua 30 lần đăng nhập sai.

Nếu IP đó thuộc khu vực Việt Nam, sẽ chỉ cảnh báo qua Telegram mà không có bất cứ hành động gì.

Nếu IP đó khác khu vực Việt Nam, tool sẽ tự động BAN IP và thông báo qua Telegram
