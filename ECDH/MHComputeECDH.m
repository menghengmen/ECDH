//
//  MHComputeECDH.m
//  GMOpenSSL (OCDemo)
//
//  Created by 哈哈 on 2022/7/23.
//

#import "MHComputeECDH.h"
#import "GMUtils.h"


#import <openssl/sm2.h>
#import <openssl/bn.h>
#import <openssl/evp.h>
#import <openssl/asn1t.h>

// 默认椭圆曲线类型 NID_sm2
static int kDefaultEllipticCurveType = NID_sm2;

@implementation MHComputeECDH

/// MARK: - ECDH 密钥协商
+ (nullable NSString *)computeECDH:(NSString *)publicKey privateKey:(NSString *)privateKey{
    if (!publicKey || publicKey.length == 0 || !privateKey || privateKey.length == 0) {
           return nil;
       }
       
       const char *public_key = publicKey.UTF8String;
       const char *private_key = privateKey.UTF8String; // 私钥
       EC_GROUP *group = EC_GROUP_new_by_curve_name(kDefaultEllipticCurveType); // 椭圆曲线
       
       EC_POINT *pub_point = NULL;  // 公钥
       BIGNUM *pri_big_num = NULL; // 私钥
       EC_KEY *key = NULL;  // 密钥结构体
       NSString *ecdhStr = nil; // 协商出的密钥字符

       do {
           // 公钥转换为 EC_POINT
           pub_point = EC_POINT_new(group);
           EC_POINT_hex2point(group, public_key, pub_point, NULL);
           // 私钥转换为 BIGNUM 并存储在 EC_KEY 中
           if (!BN_hex2bn(&pri_big_num, private_key)) {
               break;
           }
           key = EC_KEY_new();
           if (!EC_KEY_set_group(key, group)) {
               break;
           }
           if (!EC_KEY_set_private_key(key, pri_big_num)) {
               break;
           }
           
           size_t outlen = 32;
           uint8_t *ecdh_text = (uint8_t *)OPENSSL_zalloc(outlen + 1);
           int ret = ECDH_compute_key(ecdh_text, outlen, pub_point, key, 0);
           if (ret <= 0) {
               break;
           }
           NSData *ecdhData = [NSData dataWithBytes:ecdh_text length:outlen];
           ecdhStr = [GMUtils dataToHex:ecdhData];
           
           OPENSSL_free(ecdh_text);
       } while (NO);
       
       if (group != NULL) EC_GROUP_free(group);
       EC_POINT_free(pub_point);
       BN_free(pri_big_num);
       EC_KEY_free(key);
       
       return ecdhStr;
    
}

///MARK: - 创建公私钥对

+ (NSArray<NSString *> *)createKeyPair{
    NSArray<NSString *> *keyArray = @[@"", @""];
    EC_GROUP *group = EC_GROUP_new_by_curve_name(kDefaultEllipticCurveType); // 椭圆曲线
    EC_KEY *key = NULL; // 密钥对
    do {
        key = EC_KEY_new();
        if (!EC_KEY_set_group(key, group)) {
            break;
        }
        if (!EC_KEY_generate_key(key)) {
            break;
        }
        const EC_POINT *pub_key = EC_KEY_get0_public_key(key);
        const BIGNUM *pri_key = EC_KEY_get0_private_key(key);

        char *hex_pub = EC_POINT_point2hex(group, pub_key, EC_KEY_get_conv_form(key), NULL);
        char *hex_pri = BN_bn2hex(pri_key);
        
        NSString *pubHex = [NSString stringWithCString:hex_pub encoding:NSUTF8StringEncoding];
        NSString *priHex = [NSString stringWithCString:hex_pri encoding:NSUTF8StringEncoding];
        
        
        if (pubHex.length > 0 && priHex.length > 0) {
            NSString *priHexWithPadding = [self bnToHexPadding:priHex];
            keyArray = @[pubHex, priHexWithPadding];
        }
        OPENSSL_free(hex_pub);
        OPENSSL_free(hex_pri);
    } while (NO);
    
    if (group != NULL) EC_GROUP_free(group);
    EC_KEY_free(key);
    
    return keyArray;
}

/// BIGNUM 转 Hex 时，不足 64 位前面补 0
/// @param orginHex 原 Hex 字符串
+ (NSString *)bnToHexPadding:(NSString *)orginHex{
    if (orginHex.length == 0 || orginHex.length >= 64) {
        return orginHex;
    }
    static NSString *paddingZero = @"0000000000000000000000000000000000000000000000000000000000000000";
    NSString *padding = [paddingZero substringToIndex:(64 - orginHex.length)];
    return [NSString stringWithFormat:@"%@%@", padding, orginHex];
}

@end
