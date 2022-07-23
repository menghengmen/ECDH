//
//  MHComputeECDH.h
//  GMOpenSSL (OCDemo)
//
//  Created by 哈哈 on 2022/7/23.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface MHComputeECDH : NSObject

///MARK: - 创建公私钥对

+ (NSArray<NSString *> *)createKeyPair;

/// MARK: - ECDH 密钥协商
+ (nullable NSString *)computeECDH:(NSString *)publicKey privateKey:(NSString *)privateKey;

@end

NS_ASSUME_NONNULL_END
