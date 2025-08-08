# API 接口形式报告

## 一、基础概念

### 什么是 API？

API是应用程序编程接口，是不同软件系统之间通信的桥梁。Web API 通常基于 HTTP 协议，允许客户端与服务器之间进行数据交换。

## 二、接口传参方式分类

### 1. URL + Query 参数

**适用于：GET 请求**

示例：

```
GET /api/user?id=123&name=Tom
```

含义解析：

- `GET`：请求方法，表示获取数据
- `/api/user`：请求路径，代表“用户资源”
- `?id=123&name=Tom`：查询参数，传递 ID 和用户名

------

### 2. URL + Body（JSON 格式）

**适用于：POST、PUT 请求**

示例（HTTP 报文）：

```
POST /api/user HTTP/1.1
Host: example.com
Content-Type: application/json

{
  "id": 123,
  "name": "Tom"
}
```

其中 JSON 是一种数据格式，如下：

```json
{
  "id": 123,
  "name": "Tom"
}
```

------

### 3. URL + 表单（Form 提交）

HTML 表单示例：

```html
<form action="/api/login" method="post">
  <input name="username">
  <input name="password">
</form>
```

#### 表单两种格式：

- `application/x-www-form-urlencoded`：默认表单格式

  ```
  POST /login HTTP/1.1
  Host: example.com
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 29
  
  username=Tom&password=123456
  ```

- `multipart/form-data`：用于上传文件

  ```
  POST /upload HTTP/1.1
  Host: example.com
  Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
  Content-Length: 426
  
  ------WebKitFormBoundary7MA4YWxkTrZu0gW
  Content-Disposition: form-data; name="username"//普通字段部分
  
  Tom
  ------WebKitFormBoundary7MA4YWxkTrZu0gW
  Content-Disposition: form-data; name="file"; filename="photo.jpg"//文件上传字段
  Content-Type: image/jpeg
  
  <这里是 photo.jpg 文件的二进制内容>
  
  ------WebKitFormBoundary7MA4YWxkTrZu0gW--//用于分隔字段的 boundary
  ```

## 四、按风格分类

### 1. RESTful 风格接口

**RESTful** 是一种使用 **URL + HTTP 方法（GET/POST/PUT/DELETE）** 来操作“资源”的接口设计风格。

以路径语义化地表示资源：

```
GET    /api/users           -> 查询所有用户
GET    /api/users/123       -> 查询指定用户
POST   /api/users           -> 创建用户
PUT    /api/users/123       -> 更新用户
DELETE /api/users/123       -> 删除用户
```

```
POST /users HTTP/1.1
Host: api.example.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6...

{
  "name": "Alice",
  "email": "alice@example.com",
  "age": 25
}
```

```
GET /users?age=25&page=2 HTTP/1.1
```



### 2.GraphQL 接口

非 REST 接口，用于按需获取字段：

```http
POST /graphql HTTP/1.1
Host: api.example.com
Content-Type: application/json

{
  "query": "query GetUser($id: ID!) { user(id: $id) { id name email } }",
  "variables": {
    "id": "123"
  }
}

```

------

## 五、总结

| 接口方式                   | 方法     | 数据位置 | 用途              |
| -------------------------- | -------- | -------- | ----------------- |
| URL 查询参数               | GET      | URL      | 简单数据查询      |
| JSON 请求体                | POST/PUT | Body     | 创建/更新复杂数据 |
| 表单 x-www-form-urlencoded | POST     | Body     | 登录、表单提交    |
| 表单 multipart/form-data   | POST     | Body     | 文件上传          |
| RESTful 风格               | 任意     | URL+Body | 标准 Web 服务风格 |
| GraphQL                    | POST     | Body     | 灵活字段查询      |
