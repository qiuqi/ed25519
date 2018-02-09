ed25519
=====

An OTP library

Build
-----
```
使用ed25519加解密消息
application:ensure_all_started(ed25519).
{ok, BoxPubHex, BoxSecHex, SignPubHex, , SignSecHex} = ed25519:newkey().
ed25519:setkey(BoxPubHex, SignPubHex, BoxSecHex, SignSecHex).
ed25519:encrypt(PeerPub, Message).
ed25519:decrypt(PeerPub, Nonce, MsgKey, MsgCipher).
ed25519:sign(Message).
```
