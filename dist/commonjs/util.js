"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.decamelize = exports.readableToBytes = exports.createRequestId = exports.verifySignatureV3 = exports.signatureV3 = exports.sign = exports.aesDecrypt = exports.aesEncrypt = exports.aesDecryptText = exports.aesEncryptText = exports.ALIPAY_ALGORITHM_MAPPING = void 0;
const util_1 = require("util");
const crypto_1 = require("crypto");
const utility_1 = require("utility");
const snakecase_keys_1 = __importDefault(require("snakecase-keys"));
const crypto_js_1 = __importDefault(require("crypto-js"));
const debug = (0, util_1.debuglog)('alipay-sdk:util');
exports.ALIPAY_ALGORITHM_MAPPING = {
    RSA: 'RSA-SHA1',
    RSA2: 'RSA-SHA256',
};
// https://opendocs.alipay.com/common/02mse3#NodeJS%20%E8%A7%A3%E5%AF%86%E7%A4%BA%E4%BE%8B
// 初始向量的方法, 全部为0. 这里的写法适合于其它算法,针对AES算法的话,IV值一定是128位的(16字节)
// https://opendocs.alipay.com/open-v3/054l3e?pathHash=5d1dc939#%E8%AF%B7%E6%B1%82%E6%8A%A5%E6%96%87%E5%8A%A0%E5%AF%86
const IV = crypto_js_1.default.enc.Hex.parse('00000000000000000000000000000000');
function parseKey(aesKey) {
    return {
        iv: IV,
        key: crypto_js_1.default.enc.Base64.parse(aesKey),
    };
}
function aesEncryptText(plainText, aesKey) {
    const { iv, key } = parseKey(aesKey);
    const encryptedText = crypto_js_1.default.AES.encrypt(plainText, key, { iv }).toString();
    return encryptedText;
}
exports.aesEncryptText = aesEncryptText;
function aesDecryptText(encryptedText, aesKey) {
    const { iv, key } = parseKey(aesKey);
    const bytes = crypto_js_1.default.AES.decrypt(encryptedText, key, { iv });
    const plainText = bytes.toString(crypto_js_1.default.enc.Utf8);
    return plainText;
}
exports.aesDecryptText = aesDecryptText;
// 先加密后加签，aesKey 是支付宝开放平台返回的 base64 格式加密 key
function aesEncrypt(data, aesKey) {
    const plainText = JSON.stringify(data);
    return aesEncryptText(plainText, aesKey);
}
exports.aesEncrypt = aesEncrypt;
// 解密
function aesDecrypt(encryptedText, aesKey) {
    const plainText = aesDecryptText(encryptedText, aesKey);
    const decryptedData = JSON.parse(plainText);
    return decryptedData;
}
exports.aesDecrypt = aesDecrypt;
/**
 * OpenAPI 2.0 签名
 * @description https://opendocs.alipay.com/common/02kf5q
 * @param {string} method 调用接口方法名，比如 alipay.ebpp.bill.add
 * @param {object} params 请求参数
 * @param {object} config sdk 配置
 */
function sign(method, params, config, options) {
    const signParams = {
        method,
        appId: config.appId,
        charset: config.charset,
        version: config.version,
        signType: config.signType,
        timestamp: (0, utility_1.YYYYMMDDHHmmss)(),
    };
    for (const key in params) {
        if (key === 'bizContent' || key === 'biz_content' || key === 'needEncrypt')
            continue;
        signParams[key] = params[key];
    }
    if (config.appCertSn && config.alipayRootCertSn) {
        signParams.appCertSn = config.appCertSn;
        signParams.alipayRootCertSn = config.alipayRootCertSn;
    }
    if (config.wsServiceUrl) {
        signParams.wsServiceUrl = config.wsServiceUrl;
    }
    // 兼容官网的 biz_content;
    if (params.bizContent && params.biz_content) {
        throw new TypeError('不能同时设置 bizContent 和 biz_content');
    }
    let bizContent = params.bizContent ?? params.biz_content;
    if (bizContent) {
        if (options?.bizContentAutoSnakeCase !== false) {
            bizContent = (0, snakecase_keys_1.default)(bizContent);
        }
        // AES加密
        if (params.needEncrypt) {
            if (!config.encryptKey) {
                throw new TypeError('请设置 encryptKey 参数');
            }
            signParams.encryptType = 'AES';
            signParams.bizContent = aesEncrypt(bizContent, config.encryptKey);
        }
        else {
            signParams.bizContent = JSON.stringify(bizContent);
        }
    }
    // params key 驼峰转下划线
    const decamelizeParams = (0, snakecase_keys_1.default)(signParams);
    // 排序
    // ignore biz_content
    const signString = Object.keys(decamelizeParams).sort()
        .map(key => {
        let data = decamelizeParams[key];
        if (Array.prototype.toString.call(data) !== '[object String]') {
            data = JSON.stringify(data);
        }
        // return `${key}=${iconv.encode(data, config.charset!)}`;
        return `${key}=${data}`;
    })
        .join('&');
    // 计算签名
    const algorithm = exports.ALIPAY_ALGORITHM_MAPPING[config.signType];
    decamelizeParams.sign = (0, crypto_1.createSign)(algorithm)
        .update(signString, 'utf8').sign(config.privateKey, 'base64');
    debug('algorithm: %s, signString: %o, sign: %o', algorithm, signString, decamelizeParams.sign);
    return decamelizeParams;
}
exports.sign = sign;
/** OpenAPI 3.0 签名，使用应用私钥签名 */
function signatureV3(signString, appPrivateKey) {
    return (0, crypto_1.createSign)('RSA-SHA256')
        .update(signString, 'utf-8')
        .sign(appPrivateKey, 'base64');
}
exports.signatureV3 = signatureV3;
/** OpenAPI 3.0 验签，使用支付宝公钥验证签名 */
function verifySignatureV3(signString, expectedSignature, alipayPublicKey) {
    return (0, crypto_1.createVerify)('RSA-SHA256')
        .update(signString, 'utf-8')
        .verify(alipayPublicKey, expectedSignature, 'base64');
}
exports.verifySignatureV3 = verifySignatureV3;
function createRequestId() {
    return (0, crypto_1.randomUUID)().replaceAll('-', '');
}
exports.createRequestId = createRequestId;
async function readableToBytes(stream) {
    const chunks = [];
    let chunk;
    let totalLength = 0;
    for await (chunk of stream) {
        chunks.push(chunk);
        totalLength += chunk.length;
    }
    return Buffer.concat(chunks, totalLength);
}
exports.readableToBytes = readableToBytes;
/* c8 ignore start */
// forked from https://github.com/sindresorhus/decamelize/blob/main/index.js
function decamelize(text) {
    const separator = '_';
    const preserveConsecutiveUppercase = false;
    if (typeof text !== 'string') {
        throw new TypeError('The `text` arguments should be of type `string`');
    }
    // Checking the second character is done later on. Therefore process shorter strings here.
    if (text.length < 2) {
        return preserveConsecutiveUppercase ? text : text.toLowerCase();
    }
    const replacement = `$1${separator}$2`;
    // Split lowercase sequences followed by uppercase character.
    // `dataForUSACounties` → `data_For_USACounties`
    // `myURLstring → `my_URLstring`
    const decamelized = text.replace(/([\p{Lowercase_Letter}\d])(\p{Uppercase_Letter})/gu, replacement);
    if (preserveConsecutiveUppercase) {
        return handlePreserveConsecutiveUppercase(decamelized, separator);
    }
    // Split multiple uppercase characters followed by one or more lowercase characters.
    // `my_URLstring` → `my_ur_lstring`
    return decamelized
        .replace(/(\p{Uppercase_Letter})(\p{Uppercase_Letter}\p{Lowercase_Letter}+)/gu, replacement)
        .toLowerCase();
}
exports.decamelize = decamelize;
function handlePreserveConsecutiveUppercase(decamelized, separator) {
    // Lowercase all single uppercase characters. As we
    // want to preserve uppercase sequences, we cannot
    // simply lowercase the separated string at the end.
    // `data_For_USACounties` → `data_for_USACounties`
    decamelized = decamelized.replace(/((?<![\p{Uppercase_Letter}\d])[\p{Uppercase_Letter}\d](?![\p{Uppercase_Letter}\d]))/gu, $0 => $0.toLowerCase());
    // Remaining uppercase sequences will be separated from lowercase sequences.
    // `data_For_USACounties` → `data_for_USA_counties`
    return decamelized.replace(/(\p{Uppercase_Letter}+)(\p{Uppercase_Letter}\p{Lowercase_Letter}+)/gu, (_, $1, $2) => $1 + separator + $2.toLowerCase());
}
/* c8 ignore stop */
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidXRpbC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy91dGlsLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7OztBQUFBLCtCQUFnQztBQUNoQyxtQ0FBOEQ7QUFHOUQscUNBQXlDO0FBQ3pDLG9FQUEyQztBQUMzQywwREFBaUM7QUFHakMsTUFBTSxLQUFLLEdBQUcsSUFBQSxlQUFRLEVBQUMsaUJBQWlCLENBQUMsQ0FBQztBQUU3QixRQUFBLHdCQUF3QixHQUFHO0lBQ3RDLEdBQUcsRUFBRSxVQUFVO0lBQ2YsSUFBSSxFQUFFLFlBQVk7Q0FDbkIsQ0FBQztBQUVGLDBGQUEwRjtBQUMxRiwwREFBMEQ7QUFDMUQsc0hBQXNIO0FBQ3RILE1BQU0sRUFBRSxHQUFHLG1CQUFRLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsa0NBQWtDLENBQUMsQ0FBQztBQUV0RSxTQUFTLFFBQVEsQ0FBQyxNQUFjO0lBQzlCLE9BQU87UUFDTCxFQUFFLEVBQUUsRUFBRTtRQUNOLEdBQUcsRUFBRSxtQkFBUSxDQUFDLEdBQUcsQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQztLQUN2QyxDQUFDO0FBQ0osQ0FBQztBQUVELFNBQWdCLGNBQWMsQ0FBQyxTQUFpQixFQUFFLE1BQWM7SUFDOUQsTUFBTSxFQUFFLEVBQUUsRUFBRSxHQUFHLEVBQUUsR0FBRyxRQUFRLENBQUMsTUFBTSxDQUFDLENBQUM7SUFDckMsTUFBTSxhQUFhLEdBQUcsbUJBQVEsQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLFNBQVMsRUFBRSxHQUFHLEVBQUUsRUFBRSxFQUFFLEVBQUUsQ0FBQyxDQUFDLFFBQVEsRUFBRSxDQUFDO0lBQzlFLE9BQU8sYUFBYSxDQUFDO0FBQ3ZCLENBQUM7QUFKRCx3Q0FJQztBQUVELFNBQWdCLGNBQWMsQ0FBQyxhQUFxQixFQUFFLE1BQWM7SUFDbEUsTUFBTSxFQUFFLEVBQUUsRUFBRSxHQUFHLEVBQUUsR0FBRyxRQUFR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