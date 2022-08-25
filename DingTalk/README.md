# Dcry-Browser
`C++`分支

钉钉本地数据库信息获取

钉钉的数据库位于`C:/Users/%username%/AppData/Roaming/DingTalk/uid_v2/DBFiles/dingtalk.db`,其中`uid`与特定的用户绑定，是用户的身份表示。
这个数据库是加密的，加密的密钥就是`uid`取`md5`,经过一次编码,作为数据库加密密钥。加密采用`AES-128`。示例程序见`main`。

## END

仅供学习参考！
