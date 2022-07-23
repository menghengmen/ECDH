//
//  ViewController.m
//  ECDH
//
//  Created by 哈哈 on 2022/7/23.
//  Copyright © 2022 MengHeng. All rights reserved.
//

#import "ViewController.h"
#import "MHComputeECDH.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    //客户端生成一对公私钥
    NSArray *clientKey = [MHComputeECDH createKeyPair];
    NSString *clientPublicKey = clientKey[0];
    NSString *clientPrivateKey = clientKey[1];
    
    // 服务端server生成一对公私钥
    NSArray *serverKey = [MHComputeECDH createKeyPair];
    NSString *servePublicKey = serverKey[0];
    NSString *servePrivateKey = serverKey[1];
    
   // 客户端client从服务端server获取公钥sPubKey，client协商出32字节对称密钥clientECDH，转Hex后为64字节
    NSString *clientECDH = [MHComputeECDH computeECDH:servePublicKey privateKey:clientPrivateKey];
    
    // 客户端client将公钥cPubKey发送给服务端server，server协商出32字节对称密钥serverECDH，转Hex后为64字节
    NSString *serverECDH = [MHComputeECDH computeECDH:clientPublicKey privateKey:servePrivateKey];
    
    if ([clientECDH isEqualToString:serverECDH]) {
        NSLog(@"ECDH 密钥协商成功，协商出的对称密钥为：\n%@", clientECDH);
    }else{
        NSLog(@"ECDH 密钥协商失败");
    }

}


@end
