# 知识储备
需要理解如何利用格式化字符串漏洞修改栈内容。以下讲解做题过程。
***
# 做题过程
1. 启动靶场，下载二进制文件
>![image](https://github.com/user-attachments/assets/f3946636-d6dc-4a90-ad03-18c325a4acf4)
2. checksec 二进制文件，发现是32位程序，且开启了Canary保护 无法进行栈溢出
>![image](https://github.com/user-attachments/assets/e660ce96-f61e-4b8d-a926-6de8fa3f1120)
3.



   

