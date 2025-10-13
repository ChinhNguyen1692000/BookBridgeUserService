# BookBridge Backend

## Giới thiệu

BookBridge Backend là dự án backend viết bằng C# (.NET 8), dùng kiến trúc Microservices và Saga Pattern, phục vụ nền tảng quản lý các nhà sách. Hệ thống cung cấp API cho 2 frontend: Web app và Mobile app. Nền tảng cho phép người dùng tạo tài khoản, tìm kiếm nhà sách, truy cập từng nhà sách để tìm, mua, đặt sách, tìm nhà sách lân cận, có AI hỗ trợ tìm kiếm và gợi ý sách. Chủ nhà sách có thể đăng ký tài khoản, upload sách, quản lý đơn hàng, doanh thu. Admin quản lý tài khoản, người dùng, chủ nhà sách, tiệm sách, doanh thu và hoạt động hệ thống.

## Công nghệ sử dụng

* Ngôn ngữ & Framework: C# (.NET 8)
* Kiến trúc: Microservices, Saga Pattern
* Database: MySQL
* IDE: Visual Studio 2022 / Visual Studio Code
* Quản lý phiên bản: Git, GitHub
* AI: Custom finetune model hỗ trợ gợi ý và tìm kiếm sách

## Cấu trúc project

```
BookBridgeBackend/
├─ UserService/          # Quản lý người dùng, đăng ký, đăng nhập
├─ BookstoreService/     # Quản lý nhà sách, sách, đơn hàng, doanh thu
├─ AdminService/         # Quản lý người dùng, chủ nhà sách, thống kê
├─ SharedKernel/         # Module dùng chung (DTOs, Enums, Exceptions)
└─ API/                  # API gateway hoặc các endpoint tổng hợp
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

5. Cấu hình kết nối database trong `appsettings.json` mỗi microservice:

```json
"ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=UserServiceDB;Uid=root;Pwd=123456;"
}
```

## Cách chạy project

* Mở Visual Studio → chọn project → `Set as Startup Project` → Run
* Hoặc dùng CLI:

```bash
cd UserService
dotnet run
```

* Chạy API Gateway (nếu có) để tổng hợp các endpoint
* Kiểm tra API bằng Postman / Swagger UI: `http://localhost:<port>/swagger`

## Hướng dẫn Git

* Tạo branch mới khi phát triển tính năng:

```bash
git checkout -b feature/<tên-tính-năng>
```

* Commit code:

```bash
git add .
git commit -m "Mô tả tính năng/bugfix"
```

* Push lên GitHub:

```bash
git push origin feature/<tên-tính-năng>
```

* Merge vào main thông qua Pull Request trên GitHub

## Các tính năng chính

**Người dùng:** Đăng ký, đăng nhập, tìm kiếm nhà sách và sách, truy cập nhà sách, đặt/mua sách, tìm nhà sách lân cận, gợi ý sách AI.
**Chủ nhà sách:** Đăng ký tài khoản, upload và quản lý sách, quản lý đơn hàng, doanh thu.
**Admin:** Quản lý người dùng, chủ nhà sách, tiệm sách, doanh thu, thống kê và quản lý hoạt động hệ thống.

## Hướng dẫn tích hợp AI

* Gọi module AI để gợi ý sách, phân tích hành vi người dùng, tìm kiếm thông minh (semantic search)
* AI sử dụng model finetune trên dữ liệu nhà sách và người dùng

## Lưu ý

* Mỗi microservice chạy riêng lẻ, kết nối qua API Gateway hoặc HTTP client
* Database có thể tự tạo bảng khi chạy lần đầu nhờ EF Core migrations
* Luôn tạo branch riêng khi thêm tính năng mới để tránh ảnh hưởng main

## License

* Project sử dụng MIT License (hoặc license bạn chọn)
