# BookBridge Backend

## Giới thiệu

BookBridge Backend là hệ thống backend được xây dựng bằng C# (.NET 8), ứng dụng kiến trúc Microservices kết hợp với Saga Pattern, nhằm hỗ trợ nền tảng quản lý nhà sách hiện đại. Hệ thống cung cấp API cho cả Web app và Mobile app, cho phép người dùng tạo tài khoản, tìm kiếm nhà sách, truy cập từng cửa hàng để tìm, đặt hoặc mua sách, đồng thời hỗ trợ tìm nhà sách lân cận với AI gợi ý thông minh. Chủ nhà sách có thể đăng ký tài khoản, upload và quản lý sách, theo dõi đơn hàng và doanh thu. Admin có khả năng quản lý người dùng, chủ nhà sách, cửa hàng, doanh thu và toàn bộ hoạt động của hệ thống.

## Công nghệ sử dụng

* Ngôn ngữ & Framework: C# (.NET 8)
* Kiến trúc: Microservices, Saga Pattern
* Database: MySQL
* IDE: Visual Studio 2022 / Visual Studio Code
* Quản lý phiên bản: Git, GitHub
* AI: Tích hợp model finetune hỗ trợ gợi ý và tìm kiếm sách

## Cấu trúc project

```
BookBridgeBackend/
├─ UserService/          # Quản lý người dùng, đăng ký, đăng nhập
├─ BookstoreService/     # Quản lý nhà sách, sách, đơn hàng và doanh thu
├─ AdminService/         # Quản lý người dùng, chủ nhà sách và thống kê
├─ SharedKernel/         # Các module dùng chung (DTOs, Enums, Exceptions)
└─ API/                  # API Gateway hoặc các endpoint tổng hợp
```

## Hướng dẫn cài đặt môi trường

1. Cài đặt .NET 8 SDK: [Download .NET SDK](https://dotnet.microsoft.com/en-us/download/dotnet/8.0)
2. Cài đặt MySQL (>= 8.0) và tạo database:

```sql
CREATE DATABASE UserServiceDB;
CREATE DATABASE BookstoreDB;
CREATE DATABASE AdminDB;
```

3. Cài đặt Visual Studio 2022 hoặc VS Code (với extension C# nếu dùng VS Code)
4. Clone project từ GitHub:

```bash
git clone https://github.com/<organization>/bookbridge-backend.git
cd bookbridge-backend
```

5. Cấu hình kết nối database trong `appsettings.json` cho từng microservice:

```json
"ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=UserServiceDB;Uid=root;Pwd=123456;"
}
```

## Cách chạy project

* Mở Visual Studio → chọn project → `Set as Startup Project` → Run
* Hoặc sử dụng CLI:

```bash
cd UserService
dotnet run
```

* Chạy API Gateway (nếu có) để tổng hợp các endpoint
* Kiểm tra API bằng Postman hoặc Swagger UI: `http://localhost:<port>/swagger`

## Hướng dẫn Git

* Tạo branch mới khi phát triển tính năng:

```bash
git checkout -b feature/<tên-tính-năng>
```

* Commit code:

```bash
git add .
git commit -m "Mô tả tính năng hoặc sửa lỗi"
```

* Push lên GitHub:

```bash
git push origin feature/<tên-tính-năng>
```

* Merge vào main thông qua Pull Request trên GitHub

## Các tính năng chính

**Người dùng:** Đăng ký, đăng nhập, tìm kiếm nhà sách và sách, truy cập cửa hàng, đặt/mua sách, tìm nhà sách lân cận, gợi ý sách bằng AI.
**Chủ nhà sách:** Đăng ký tài khoản, upload và quản lý sách, theo dõi đơn hàng và doanh thu.
**Admin:** Quản lý người dùng, chủ nhà sách, cửa hàng, doanh thu và thống kê toàn bộ hoạt động.

## Hướng dẫn tích hợp AI

* Gọi module AI để gợi ý sách, phân tích hành vi người dùng, thực hiện tìm kiếm thông minh (semantic search)
* Sử dụng model finetune dựa trên dữ liệu nhà sách và người dùng

## Lưu ý

* Mỗi microservice chạy riêng biệt, kết nối qua API Gateway hoặc HTTP client
* Database có thể tự tạo bảng khi chạy lần đầu nhờ EF Core migrations
* Luôn phát triển trên branch riêng để tránh ảnh hưởng main

