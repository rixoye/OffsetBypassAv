# OffsetBypassAv


### 免杀思路
随机找一个包含`0-f`的字符串，将shellcode用该字符串的偏移量进行解析，输出偏移量数组。

实际加载时再从该随机字符串中提取对应的字符拼接，形成shellcode后再执行。

### 部分代码讲述
OffsetClac文件夹下是计算偏移的代码，shellcode和随机字符串自个替换就可以使用了，计算偏移过程中，只要注意一下，16进制和ASCII码字符的转换就好了。

Loader文件夹下是一个shellcode加载器，在shellcode的加载器中，我使用了Windows系统回调函数触发shellcode的方式，代码中仅写了x64下的，x86下的要自个重新计算CreateFiber函数的回调函数偏移量。

### 实际免杀效果
由于没有去做反沙箱的手段，所以沙箱运行的内存识别还是发现了msf的shellcode特征。
url：https://www.virscan.org/report/afaaee5837f656499f91cd37fca8fa78a597df1ff66bcc716282c982fb6d268d
<img width="1172" alt="image" src="https://user-images.githubusercontent.com/109727407/183383226-fc31288b-aa93-4d40-93fc-d604fff6aaf0.png">


### 代码
https://github.com/rixoye/OffsetBypassAv
