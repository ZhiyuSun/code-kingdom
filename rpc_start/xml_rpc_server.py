from xmlrpc.server import SimpleXMLRPCServer

#python中类的命名方式遵循驼峰命名法
#1. 没有出现url的映射
#2. 没有编码和解码
#序列化和反序列化协议是 xml json
class Calculater:
    def add(self, x, y):
        return x + y
    def multiply(self, x, y):
        return x * y
    def subtract(self, x, y):
        return abs(x-y)
    def divide(self, x, y):
        return x/y

obj = Calculater()
server = SimpleXMLRPCServer(("localhost", 8088))
# 将实例注册给rpc server
server.register_instance(obj)
print("Listening on port 8088")
server.serve_forever()

# 1. 超时机制
# 2. 限流，处于长期可用状态-高可用
# 3. 解耦
# 4. 负载均衡，微服务 - 分布式应用的一种具体的体现
# 5. 序列化和反序列化数据压缩是否高效 json这种数据格式已经非常的简单了 1.这个序列化协议能将数据的压缩变得更小 2. 这个序列化和反序列化的速度够快
# #json.dumps() json.loads()
# #做架构 技术选型的时候 这些都是我们需要考虑到的点
# 6. 这个rpc框架是否支持多语言 生态很好