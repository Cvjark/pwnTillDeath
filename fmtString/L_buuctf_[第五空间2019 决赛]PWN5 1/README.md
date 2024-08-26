# 前言
不经常写笔记，写得有点潦草，有啥问题直接问本人~@蔡师傅
***

# 知识储备
需要理解如何利用格式化字符串漏洞修改栈内容。  

以下讲解做题过程。
***

# 做题过程
1. 启动靶场，下载二进制文件
>![image](https://github.com/user-attachments/assets/f3946636-d6dc-4a90-ad03-18c325a4acf4)
2. checksec 二进制文件，发现是32位程序，且开启了Canary保护 无法进行栈溢出
>![image](https://github.com/user-attachments/assets/e660ce96-f61e-4b8d-a926-6de8fa3f1120)  
3. 拖到ida分析，**发现可以操控printf函数的输入，因此考察格式化字符串漏洞**。代码逻辑是先随机生成一个随机数放在dword_804C044处，最后和用户输入的数据进行比较，一致则拿到shell。在ida中双击查看dword_804C044地址为0x0804C044。我们不知道随机生成的数是多少，因此需要利用格式化字符串漏洞修改0x0804C044处的值，才能拿到shell
>![image](https://github.com/user-attachments/assets/752a986c-028c-49b2-95ff-c5e8537c5e35)  
4. 现在需要调试程序，查看**我们的输入**距离**printf函数**的栈中距离
>试探输入：AAAA-%p-%p-%p-%p-%p-%p-%p-%p-%p
>栈中位置：
>![image](https://github.com/user-attachments/assets/ef53fd89-1165-4fb9-af2b-7252cb0fd4e7)
>可以数一下，刚好在第10个位置
>因此构造printf的输入为：
>addr(0x0804C044)+%10&n
>%10&n可以将栈中第10处读到的地址修改为 printf已经打印出的字符数，也就是已经打印的字节数

5. 因此exp如下：
>![image](https://github.com/user-attachments/assets/b2d3c493-2eb7-4eca-a814-e3a51e64e43b)
6. cat flag，结束此题。
>![image](https://github.com/user-attachments/assets/ac75657e-5999-4d63-aa29-cfd7c09ab1a6)






   

