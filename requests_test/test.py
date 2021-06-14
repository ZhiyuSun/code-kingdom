import requests
from collections import abc

# 测试1
# rsp = requests.post("http://127.0.0.1:8083/form_post", data={
#     "message":"你好",
#     "nick":"孙志宇"
# })
# print(rsp.text)


# 测试2
# rsp = requests.post("http://127.0.0.1:8083/post?id=1&page=2", data={
#     "name":"孙志宇",
#     "message":"你好"
# })
# print(rsp.text)

# 测试3
# from requests_test.proto import user_pb2
#
# user = user_pb2.Teacher()
#
# rsp = requests.get("http://127.0.0.1:8083/someProtoBuf")
# user.ParseFromString(rsp.content)
# print(user.name, user.course) # sunzhiyu ['python', 'go', '微服务']

# import requests
#
# #登录
# rsp = requests.post("http://127.0.0.1:8083/loginJSON", json={
#     "user":"bo",
#     "password":"imooc"
# })
# print(rsp.text)

#注册
# rsp = requests.post("http://127.0.0.1:8083/signup", json={
#     "age":18,
#     "name":"sunzhiyu",
#     "email":"12@qq.com",
#     "password":"imooc",
#     "re_password":"imooc"
# })
# print(rsp.text)


rsp = requests.get("http://127.0.0.1:8083/ping", headers={
    "x-token":"sunzhiyu"
})
print(rsp.text)
