from func_paras import *
import tkinter as tk
from tkinter import messagebox

def mainUI():
    # 加密按钮点击事件
    def encrypt_button_click():
        window.destroy()
        encryptionUI()

    # 解密按钮点击事件
    def decrypt_button_click():
        window.destroy()
        decryptionUI()

    # 密钥破解按钮点击事件
    def crack_button_click():
        window.destroy()
        crackUI()

    # 创建主窗口
    window = tk.Tk()
    window.title("S-AES算法")
    window.geometry("600x450")

    # 设置Label
    label = tk.Label(window, text="S-AES算法", font=("Helvetica", 24))
    label.place(relx=0.5, rely=0.4, anchor="center")

    # 设置加密按钮
    encrypt_button = tk.Button(window, text="加密", width=10, command=encrypt_button_click)
    encrypt_button.place(relx=0.3, rely=0.65, anchor="center")

    # 设置解密按钮
    decrypt_button = tk.Button(window, text="解密", width=10, command=decrypt_button_click)
    decrypt_button.place(relx=0.5, rely=0.65, anchor="center")

    # 设置密钥破解按钮
    crack_button = tk.Button(window, text="密钥破解", width=10, command=crack_button_click)
    crack_button.place(relx=0.7, rely=0.65, anchor="center")

    label.configure(bg="lightblue")

    encrypt_button.configure(bg="lightgreen")
    decrypt_button.configure(bg="lightcoral")
    crack_button.configure(bg="lightgoldenrodyellow")
    window.configure(bg="white")

    # 运行主循环
    window.mainloop()
def encryptionUI():
    # 返回按钮点击事件
    def return_button_click():
        encryption_screen.destroy()
        mainUI()

    encryption_screen = tk.Tk()
    encryption_screen.title("加密")
    encryption_screen.geometry("600x450")

    # 明文输入框
    plaintextLabel = tk.Label(encryption_screen, text="明文", font=("Helvetica", 12))
    plaintextLabel.place(relx=0.1, rely=0.1, anchor="nw")
    plaintext_entry = tk.Entry(encryption_screen, font=("Helvetica", 12), width=45)
    plaintext_entry.place(relx=0.2, rely=0.1, anchor="nw")

    # 密钥1输入框
    key1Label = tk.Label(encryption_screen, text="密钥1", font=("Helvetica", 12))
    key1Label.place(relx=0.1, rely=0.2, anchor="nw")
    key1_entry = tk.Entry(encryption_screen, font=("Helvetica", 12), width=45)
    key1_entry.place(relx=0.2, rely=0.2, anchor="nw")

    # 密钥2输入框
    key2Label = tk.Label(encryption_screen, text="密钥2", font=("Helvetica", 12))
    key2Label.place(relx=0.1, rely=0.3, anchor="nw")
    key2_entry = tk.Entry(encryption_screen, font=("Helvetica", 12), width=45)
    key2_entry.place(relx=0.2, rely=0.3, anchor="nw")
    key2_entry.insert(0, "一重加密和CBC加密时，此框不需要输入")

    # 结果输出框
    resultLabel = tk.Label(encryption_screen, text="结果", font=("Helvetica", 12))
    resultLabel.place(relx=0.1, rely=0.4, anchor="nw")
    result_out = tk.Entry(encryption_screen, font=("Helvetica", 12), width=45)
    result_out.place(relx=0.2, rely=0.4, anchor="nw")

    # 加密对象选择框
    encryptioner_label = tk.Label(encryption_screen, text="加密对象", font=("Helvetica", 12))
    encryptioner_label.place(relx=0.4, rely=0.55, anchor="center")
    encryption_target = tk.StringVar(encryption_screen)
    encryption_target.set("二进制字符串")
    encryption_target_dropdown = tk.OptionMenu(encryption_screen, encryption_target, "二进制字符串", "ASCII码")
    encryption_target_dropdown.config(font=("Helvetica", 12))
    encryption_target_dropdown.place(relx=0.6, rely=0.55, anchor="center")

    # 加密级别选择框
    encryption_way_level = tk.Label(encryption_screen, text="加密类型", font=("Helvetica", 12))
    encryption_way_level.place(relx=0.4, rely=0.65, anchor="center")
    encryption_level = tk.StringVar(encryption_screen)
    encryption_level.set("一重加密")
    encryption_level_dropdown = tk.OptionMenu(encryption_screen, encryption_level, "一重加密", "双重加密", "三重加密","CBC加密")
    encryption_level_dropdown.config(font=("Helvetica", 12))
    encryption_level_dropdown.place(relx=0.6, rely=0.65, anchor="center")


    # 加密按钮点击事件
    def on_encrypt_button_click():
        cipher_text = ""
        # 获取明文框内容、密钥框1内容、密钥框2内容以及选择框1和选择框2的内容
        plain_text = plaintext_entry.get()
        key1 = key1_entry.get()
        key2 = key2_entry.get()
        choice1 = encryption_target.get()
        choice2 = encryption_level.get()

        # 检查选择框1的选择
        if choice1 == "二进制字符串":
            # 检查选择框2的选择
            if choice2 == "一重加密":
                if not (len(plain_text) == len(key1)  == 16 and all(
                        bit in '01' for bit in plain_text + key1)):
                    result_out.delete(0, tk.END)  # 清空现有内容
                    tk.messagebox.showerror("错误", "明文、密钥1必须是十六位二进制数！")
                    return
                cipher_text = Encrypt(plain_text, key1)
            elif choice2 == "双重加密":
                if not (len(plain_text) == len(key1) ==len(key2)  == 16 and all(
                        bit in '01' for bit in plain_text + key1 + key2)):
                    result_out.delete(0, tk.END)  # 清空现有内容
                    tk.messagebox.showerror("错误", "明文、密钥1和密钥2必须是十六位二进制数！")
                    return
                cipher_text = binary_double_encrypt(plain_text, key1, key2)
            elif choice2 == "三重加密":
                if not (len(plain_text) == len(key1) == len(key2) == 16 and all(
                        bit in '01' for bit in plain_text + key1 + key2)):
                    result_out.delete(0, tk.END)  # 清空现有内容
                    tk.messagebox.showerror("错误", "明文、密钥1和密钥2必须是十六位二进制数！")
                    return
                cipher_text = binary_triple_encrypt(plain_text, key1, key2)
            elif choice2 == "CBC加密":
                if not (len(plain_text)%16==0 and len(key1)== 16 and all(
                        bit in '01' for bit in  key1 )):
                    result_out.delete(0, tk.END)  # 清空现有内容
                    tk.messagebox.showerror("错误", "明文长度需是16的倍数、密钥1和密钥2必须是十六位二进制数！")
                    return
                IV = generate_IV()
                cipher_text = binary_CBC_encrypt(plain_text, key1, IV)
                print("此次使用的IV是：",IV)
        elif choice1 == "ASCII码":
            # 检查选择框2的选择
            if choice2 == "一重加密":
                if not (plain_text  and len(key1) == 16 and all(
                        bit in '01' for bit in key1)):
                    result_out.delete(0, tk.END)  # 清空现有内容
                    tk.messagebox.showerror("错误", "明文不能为空，密钥必须是十六位二进制数！")
                    return
                cipher_text = ascii_encrypt(plain_text, key1)
            elif choice2 == "双重加密":
                if not (plain_text and  len(key1) == len(key2) == 16 and all(
                        bit in '01' for bit in key1 + key2)):
                    result_out.delete(0, tk.END)  # 清空现有内容
                    tk.messagebox.showerror("错误", "明文、密钥1和密钥2必须是十六位二进制数！")
                    return
                cipher_text = ascll_double_encrypt(plain_text, key1, key2)
            elif choice2 == "三重加密":
                if not (plain_text and  len(key1) == len(key2) == 16 and all(
                        bit in '01' for bit in  key1 + key2)):
                    result_out.delete(0, tk.END)  # 清空现有内容
                    tk.messagebox.showerror("错误", "明文、密钥1和密钥2必须是十六位二进制数！")
                    return
                cipher_text = ascll_triple_encrypt(plain_text, key1, key2)
            elif choice2 == "CBC加密":
                binary = ascii2binary(plain_text)
                if not (len(binary) % 16 == 0 and len(key1) == 16 and all(
                        bit in '01' for bit in key1)):
                    result_out.delete(0, tk.END)  # 清空现有内容
                    tk.messagebox.showerror("错误", "明文长度需是16的倍数、密钥1和密钥2必须是十六位二进制数！")
                    return
                IV = generate_IV()
                cipher_text = binary_CBC_encrypt(binary, key1, IV)
                print("此次使用的IV是：",IV)
        # 将加密结果显示在输出框中
        result_out.delete(0, tk.END)  # 清空现有内容
        result_out.insert(0, cipher_text)  # 插入新的文本

    # 加密按钮
    encrypt_button = tk.Button(encryption_screen, text="加密", font=("Helvetica", 12), width=10,
                               command=on_encrypt_button_click)
    encrypt_button.place(relx=0.3, rely=0.8, anchor="center")

    # 返回按钮
    return_button = tk.Button(encryption_screen, text="返回", font=("Helvetica", 12), width=10,
                              command=return_button_click)
    return_button.place(relx=0.7, rely=0.8, anchor="center")

    encrypt_button.configure(bg="lightgreen")
    return_button.configure(bg="lightgreen")
    encryption_screen.configure(bg="white")
    plaintextLabel.configure(bg="white")
    key2Label.configure(bg="white")
    key1Label.configure(bg="white")
    resultLabel.configure(bg="white")
    encryption_way_level.configure(bg="white")
    encryptioner_label.configure(bg="white")

    encryption_screen.mainloop()
def decryptionUI():

    def return_button_click():
        decryption_screen.destroy()
        mainUI()

    def on_decrypt_button_click():
        plain_text = ""
        # 获取密文框内容、密钥框1内容、密钥框2内容以及选择框1和选择框2的内容
        cipher_text = cipherText_Entry.get()
        key1 = key1_entry.get()
        key2 = key2_entry.get()
        choice1 = decryption_target.get()
        choice2 = decryption_level.get()
        # 检查选择框1的选择
        if choice1 == "二进制字符串":
            # 检查选择框2的选择
            if choice2 == "一重解密":
                if not (len(cipher_text) == len(key1)  == 16 and all(
                        bit in '01' for bit in plain_text + key1)):
                    result_out.delete(0, tk.END)  # 清空现有内容
                    tk.messagebox.showerror("错误", "密文、密钥1必须是十六位二进制数！")
                    return
                plain_text = Decrypt(cipher_text, key1)
            elif choice2 == "双重解密":
                if not (len(cipher_text) == len(key1) ==len(key2)  == 16 and all(
                        bit in '01' for bit in plain_text + key1 + key2)):
                    result_out.delete(0, tk.END)  # 清空现有内容
                    tk.messagebox.showerror("错误", "密文、密钥1和密钥2必须是十六位二进制数！")
                    return
                plain_text = binary_double_decrypt(cipher_text, key1, key2)
            elif choice2 == "CBC解密":
                if not (len(cipher_text) % 16 == 0 and len(key1) == 16 and all(
                        bit in '01' for bit in key1)):
                    result_out.delete(0, tk.END)  # 清空现有内容
                    tk.messagebox.showerror("错误", "明文长度需是16的倍数、密钥1和IV必须是十六位二进制数！")
                    return
                plain_text = binary_CBC_decrypt(cipher_text, key1, key2)
        elif choice1 == "ASCII码":
            # 检查选择框2的选择
            if choice2 == "一重解密":
                if not (cipher_text  and len(key1) == 16 and all(
                        bit in '01' for bit in key1)):
                    result_out.delete(0, tk.END)  # 清空现有内容
                    tk.messagebox.showerror("错误", "密文不能为空，密钥必须是十六位二进制数！")
                    return
                plain_text = ascii_decrypt(cipher_text, key1)
            elif choice2 == "双重解密":
                if not (cipher_text and  len(key1) == len(key2) == 16 and all(
                        bit in '01' for bit in key1 + key2)):
                    result_out.delete(0, tk.END)  # 清空现有内容
                    tk.messagebox.showerror("错误", "密文不能为空、密钥1和密钥2必须是十六位二进制数！")
                    return
                plain_text = ascll_double_decrypt(cipher_text, key1, key2)
            elif choice2 == "CBC解密":
                binary = ascii2binary(cipher_text)
                if not (len(binary) % 16 == 0 and len(key1) == 16 and all(
                        bit in '01' for bit in key1)):
                    result_out.delete(0, tk.END)  # 清空现有内容
                    tk.messagebox.showerror("错误", "明文长度需是16的倍数、密钥1和密钥2必须是十六位二进制数！")
                    return
                plain_text = binary_CBC_decrypt(cipher_text, key1, key2)

        # 将加密结果显示在输出框中
        result_out.delete(0, tk.END)  # 清空现有内容
        result_out.insert(0, plain_text)  # 插入新的文本

    decryption_screen = tk.Tk()
    decryption_screen.title("解密")
    decryption_screen.geometry("600x450")

    # 明文输出
    resultLabel = tk.Label(decryption_screen, text="明文", font=("Helvetica", 12))
    resultLabel.place(relx=0.1, rely=0.4, anchor="nw")
    result_out = tk.Entry(decryption_screen, font=("Helvetica", 12), width=45)
    result_out.place(relx=0.2, rely=0.4, anchor="nw")

    # 密钥1输入框
    key1Label = tk.Label(decryption_screen, text="密钥1", font=("Helvetica", 12))
    key1Label.place(relx=0.1, rely=0.2, anchor="nw")
    key1_entry = tk.Entry(decryption_screen, font=("Helvetica", 12), width=45)
    key1_entry.place(relx=0.2, rely=0.2, anchor="nw")

    # 密钥2输入框
    key2Label = tk.Label(decryption_screen, text="密钥2/IV", font=("Helvetica", 12))
    key2Label.place(relx=0.1, rely=0.3, anchor="nw")
    key2_entry = tk.Entry(decryption_screen, font=("Helvetica", 12), width=45)
    key2_entry.place(relx=0.2, rely=0.3, anchor="nw")
    key2_entry.insert(0, "一重解密时，此框不需要输入")

    # 密文输入框
    cipherTextLabel = tk.Label(decryption_screen, text="密文", font=("Helvetica", 12))
    cipherTextLabel.place(relx=0.1, rely=0.1, anchor="nw")
    cipherText_Entry = tk.Entry(decryption_screen, font=("Helvetica", 12), width=45)
    cipherText_Entry.place(relx=0.2, rely=0.1, anchor="nw")

    # 解密对象选择框
    decryptioner_label = tk.Label(decryption_screen, text="解密对象", font=("Helvetica", 12))
    decryptioner_label.place(relx=0.4, rely=0.55, anchor="center")
    decryption_target = tk.StringVar(decryption_screen)
    decryption_target.set("二进制字符串")
    decryption_target_dropdown = tk.OptionMenu(decryption_screen, decryption_target, "二进制字符串", "ASCII码")
    decryption_target_dropdown.config(font=("Helvetica", 12))
    decryption_target_dropdown.place(relx=0.6, rely=0.55, anchor="center")

    # 加密级别选择框
    decryption_way_level = tk.Label(decryption_screen, text="解密类型", font=("Helvetica", 12))
    decryption_way_level.place(relx=0.4, rely=0.65, anchor="center")
    decryption_level = tk.StringVar(decryption_screen)
    decryption_level.set("一重解密")
    decryption_level_dropdown = tk.OptionMenu(decryption_screen, decryption_level, "一重解密", "双重解密","CBC解密")
    decryption_level_dropdown.config(font=("Helvetica", 12))
    decryption_level_dropdown.place(relx=0.6, rely=0.65, anchor="center")

    # 解密按钮
    decrypt_button = tk.Button(decryption_screen, text="解密", font=("Helvetica", 12), width=10,command=on_decrypt_button_click)
    decrypt_button.place(relx=0.3, rely=0.8, anchor="center")

    # 返回按钮
    return_button = tk.Button(decryption_screen, text="返回", font=("Helvetica", 12), width=10,command=return_button_click)
    return_button.place(relx=0.7, rely=0.8, anchor="center")

    decrypt_button.configure(bg="lightgreen")
    return_button.configure(bg="lightgreen")
    decryption_screen.configure(bg="white")
    resultLabel.configure(bg="white")
    key2Label.configure(bg="white")
    key1Label.configure(bg="white")
    cipherTextLabel.configure(bg="white")
    decryption_way_level.configure(bg="white")
    decryptioner_label.configure(bg="white")

    decryption_screen.mainloop()
def crackUI():
    def return_button_click():
        crack_screen.destroy()
        mainUI()

    def on_crack_button_click():
        plain_text = plaintext_entry.get()
        # 获取密文框内容、密钥框1内容、密钥框2内容以及选择框1和选择框2的内容
        cipher_text = cipherText_Entry.get()
        key1 =  []
        key2 =  []
        choice1 = crack_target.get()
        choice2 = crack_level.get()
        # 检查选择框1的选择
        if choice1 == "二进制字符串":
            # 检查选择框2的选择
            if choice2 == "一重破解":
                if not (len(cipher_text) == len(plain_text)  == 16 and all(
                        bit in '01' for bit in plain_text + cipher_text)):
                    tk.messagebox.showerror("错误", "明文、密文必须是十六位二进制数！")
                    return
                key1 = crack(plain_text, cipher_text)
            elif choice2 == "中间相遇攻击":
                if not (is_multiple_of_16(plain_text) and is_multiple_of_16(cipher_text) and len(plain_text) == len(
                            cipher_text)):
                    tk.messagebox.showerror("错误", "明文、密文数字个数需是16的倍数且个数相同")
                    return
                # 切割 plain_text
                plainText = [plain_text[i:i + 16] for i in range(0, len(plain_text), 17)]

                # 切割 cipher_text
                cipherText = [cipher_text[i:i + 16] for i in range(0, len(cipher_text), 17)]

                # key1 = middle_meet_attack(plainText,cipherText)
                key1 = "由于中间相遇攻击结果数量太多，如需遍历，请在代码里将上面的注释打开，输出框显示不下"

        elif choice1 == "ASCII码":
            # 检查选择框2的选择
            if choice2 == "一重破解":
                if not (plain_text and cipher_text):
                    tk.messagebox.showerror("错误", "明文、密文必须是十六位二进制数！")
                    return
                key1 = crack(plain_text, cipher_text)
            elif choice2 == "中间相遇攻击":
                if not (is_multiple_of_16(plain_text) and is_multiple_of_16(cipher_text) and len(plain_text) == len(
                        cipher_text)):
                    tk.messagebox.showerror("错误", "明文、密文数字个数需是16的倍数且个数相同")
                    return
            # 切割 plain_text
            plainText = [plain_text[i:i + 16] for i in range(0, len(plain_text), 17)]

            # 切割 cipher_text
            cipherText = [cipher_text[i:i + 16] for i in range(0, len(cipher_text), 17)]

            # key1 = middle_meet_attack(plainText,cipherText)
            key1 = "由于中间相遇攻击结果数量太多，如需遍历，请在代码里将上面的注释打开，输出框显示不下"
        # 将加密结果显示在输出框中
        key1_out.delete("1.0", tk.END)  # 清空现有内容
        if(key1 == ''):
            key1_out.insert("1.0", "不存在符合条件的密钥")  # 插入新的文本
        else:
            key1_out.insert("1.0", key1)  # 插入新的文本

    crack_screen = tk.Tk()
    crack_screen.title("密钥破解")
    crack_screen.geometry("600x450")

    # 明文输入框
    plaintextLabel = tk.Label(crack_screen, text="明文", font=("Helvetica", 12))
    plaintextLabel.place(relx=0.1, rely=0.1, anchor="nw")
    plaintext_entry = tk.Entry(crack_screen, font=("Helvetica", 12), width=45)
    plaintext_entry.place(relx=0.2, rely=0.1, anchor="nw")

    # 密钥1输出框
    key1Label = tk.Label(crack_screen, text="密钥", font=("Helvetica", 12))
    key1Label.place(relx=0.1, rely=0.6, anchor="nw")
    key1_out = tk.Text(crack_screen, font=("Helvetica", 12), width=45)
    key1_out.place(relx=0.2, rely=0.6, anchor="nw")


    # 密文输入框
    cipherTextLabel = tk.Label(crack_screen, text="密文", font=("Helvetica", 12))
    cipherTextLabel.place(relx=0.1, rely=0.2, anchor="nw")
    cipherText_Entry = tk.Entry(crack_screen, font=("Helvetica", 12), width=45)
    cipherText_Entry.place(relx=0.2, rely=0.2, anchor="nw")

    # 破解对象选择框
    cracker_label = tk.Label(crack_screen, text="破解对象", font=("Helvetica", 12))
    cracker_label.place(relx=0.4, rely=0.3, anchor="center")
    crack_target = tk.StringVar(crack_screen)
    crack_target.set("二进制字符串")
    crack_target_dropdown = tk.OptionMenu(crack_screen, crack_target, "二进制字符串", "ASCII码")
    crack_target_dropdown.config(font=("Helvetica", 12))
    crack_target_dropdown.place(relx=0.6, rely=0.3, anchor="center")

    # 破解级别选择框
    crack_way_lebel = tk.Label(crack_screen, text="破解类型", font=("Helvetica", 12))
    crack_way_lebel.place(relx=0.4, rely=0.4, anchor="center")
    crack_level = tk.StringVar(crack_screen)
    crack_level.set("一重破解")
    crack_level_dropdown = tk.OptionMenu(crack_screen, crack_level, "一重破解", "中间相遇攻击")
    crack_level_dropdown.config(font=("Helvetica", 12))
    crack_level_dropdown.place(relx=0.6, rely=0.4, anchor="center")

    # 破解按钮
    crack_button = tk.Button(crack_screen, text="破解", font=("Helvetica", 12), width=10,command=on_crack_button_click)
    crack_button.place(relx=0.3, rely=0.5, anchor="center")

    # 返回按钮
    return_button = tk.Button(crack_screen, text="返回", font=("Helvetica", 12), width=10,
                              command=return_button_click)
    return_button.place(relx=0.7, rely=0.5, anchor="center")

    crack_button.configure(bg="lightgreen")
    return_button.configure(bg="lightgreen")
    crack_screen.configure(bg="white")
    plaintextLabel.configure(bg="white")
    key1Label.configure(bg="white")
    cipherTextLabel.configure(bg="white")
    cracker_label.configure(bg="white")
    crack_way_lebel.configure(bg="white")

    crack_screen.mainloop()

if __name__ == "__main__":
    mainUI()
