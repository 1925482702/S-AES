
# S-AES算法实现

## 项目简介

本项目基于S-AES（Simplified Advanced Encryption Standard）算法实现了一个加密解密程序，支持16位数据和16位密钥的输入，输出16位密文。

## 功能列表

1.  **基本功能**
    
    -   提供GUI界面，支持用户交互
    -   支持输入16位数据和16位密钥
    -   输出16位密文
2.  **交叉测试**
    
    -   使用相同算法流程和转换单元，确保程序在异构系统或平台上正常运行。
3.  **扩展功能**
    
    -   输入可以是ASII编码字符串（分组为2 Bytes）
    -   输出也可以是ACII字符串
4.  **多重加密**
    
    -   支持双重加密，密钥长度为32 bits
    -   中间相遇攻击
5.  **三重加密**
    
    -   支持两种模式：32 bits密钥交替加密
6.  **工作模式**
    
    -   使用密码分组链（CBC）模式对较长的明文消息进行加密
    -   注意初始向量（16 bits）的生成，加解密双方需要共享

## 使用说明

### 程序运行

运行 `mainUI()` 函数即可启动程序。

### 功能操作

-   加密功能：选择明文和密钥，点击“加密”按钮即可获得密文。
-   解密功能：选择密文和密钥，点击“解密”按钮即可获得明文。
-   密钥破解：提供两种方法，一重破解和中间相遇攻击。输入明文和对应的密文，选择破解类型，点击“破解”按钮即可获得密钥。

### 截图

以下是程序的运行截图：

![Screenshot1](https://github.com/1925482702/S-AES/blob/main/S-AES-RushB/image/mainUI.png)  
_图1: 主界面_

![Screenshot2](https://github.com/1925482702/S-AES/blob/main/S-AES-RushB/image/encryptUI.png)  
_图2: 加密界面_

![Screenshot2](https://github.com/1925482702/S-AES/blob/main/S-AES-RushB/image/decryptUI.png)  
_图3: 解密界面_

![Screenshot2](https://github.com/1925482702/S-AES/blob/main/S-AES-RushB/image/crackUI.png)  
_图4: 密钥破解界面_

![Screenshot2](https://github.com/1925482702/S-AES/blob/main/S-AES-RushB/image/encrypt2.png)  
_图5: 双重加密示例（更多加密示例在文件的image文件夹里）

![Screenshot2](https://github.com/1925482702/S-AES/blob/main/S-AES-RushB/image/decrypt1.png)  
_图5: 一重解密示例（更多解密示例在文件的image文件夹里）

![Screenshot2](https://github.com/1925482702/S-AES/blob/main/S-AES-RushB/image/crack.png)  
_图5: 破解示例（更多破解示例在文件的image文件夹里）

## 交叉测试

### A组同学

-   使用相同的密钥K加密明文P，得到密文C。

### B组同学

-   使用相同的密钥K解密密文C，得到明文P。
