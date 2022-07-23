# ECDH
ECDH 密钥协商  SHA256WithECDSA签名

### ECDH 密钥协商

OpenSSL 中的 `ECDH_compute_key()`执行椭圆曲线 Diffie-Hellman 密钥协商，可在双方都是明文传输的情况下，协商出一个相同的密钥。

协商流程：

1. 客户端随机生成一对公私钥 clientPublicKey，clientPrivateKey；
2. 服务端随机生成一对公私钥 serverPublicKey，serverPrivateKey；
3. 双方利用网络请求或其他方式交换公钥 clientPublicKey 和 serverPublicKey，私钥自己保存；
4. 客户端计算`clientKey = ECDH_compute_key(clientPrivateKey，serverPublicKey)`；
5. 服务端计算`serverKey = ECDH_compute_key(serverPrivateKey，clientPublicKey)`；
6. 双方各自计算出的 clientKey 和 serverKey 应该是相等的，这个 key 可以作为对称加密的密钥。
