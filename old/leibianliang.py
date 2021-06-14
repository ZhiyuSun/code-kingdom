# -*- coding: utf-8 -*-
class Student():

    # 类变量
    name = '张'
    age = 0

    def __init__(self, name, age):
        # 构造函数
        # 初始化变量的属性
        Student.name = name
        Student.age = age

    @classmethod
    def haha(cls):
        print Student.name

student1 = Student("王", 2)
print(student1.name)
print(student1.__dict__)
print(Student.name)
print(Student.__dict__)
Student.haha()
student1.haha()
print(getattr(student1, 'ss'))