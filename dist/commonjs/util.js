"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ALIPAY_ALGORITHM_MAPPING = void 0;
exports.aesEncryptText = aesEncryptText;
exports.aesDecryptText = aesDecryptText;
exports.aesEncrypt = aesEncrypt;
exports.aesDecrypt = aesDecrypt;
exports.sign = sign;
exports.signatureV3 = signatureV3;
exports.verifySignatureV3 = verifySignatureV3;
exports.createRequestId = createRequestId;
exports.readableToBytes = readableToBytes;
exports.decamelize = decamelize;
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
function aesDecryptText(encryptedText, aesKey) {
    const { iv, key } = parseKey(aesKey);
    const bytes = crypto_js_1.default.AES.decrypt(encryptedText, key, { iv });
    const plainText = bytes.toString(crypto_js_1.default.enc.Utf8);
    return plainText;
}
// 先加密后加签，aesKey 是支付宝开放平台返回的 base64 格式加密 key
function aesEncrypt(data, aesKey) {
    const plainText = JSON.stringify(data);
    return aesEncryptText(plainText, aesKey);
}
// 解密
function aesDecrypt(encryptedText, aesKey) {
    const plainText = aesDecryptText(encryptedText, aesKey);
    const decryptedData = JSON.parse(plainText);
    return decryptedData;
}
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
/** OpenAPI 3.0 签名，使用应用私钥签名 */
function signatureV3(signString, appPrivateKey) {
    return (0, crypto_1.createSign)('RSA-SHA256')
        .update(signString, 'utf-8')
        .sign(appPrivateKey, 'base64');
}
/** OpenAPI 3.0 验签，使用支付宝公钥验证签名 */
function verifySignatureV3(signString, expectedSignature, alipayPublicKey) {
    return (0, crypto_1.createVerify)('RSA-SHA256')
        .update(signString, 'utf-8')
        .verify(alipayPublicKey, expectedSignature, 'base64');
}
function createRequestId() {
    return (0, crypto_1.randomUUID)().replaceAll('-', '');
}
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidXRpbC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy91dGlsLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7OztBQTRCQSx3Q0FJQztBQUVELHdDQUtDO0FBR0QsZ0NBR0M7QUFHRCxnQ0FJQztBQWNELG9CQW1FQztBQUdELGtDQUlDO0FBR0QsOENBSUM7QUFFRCwwQ0FFQztBQUVELDBDQVNDO0FBSUQsZ0NBbUNDO0FBek1ELCtCQUFnQztBQUNoQyxtQ0FBOEQ7QUFHOUQscUNBQXlDO0FBQ3pDLG9FQUEyQztBQUMzQywwREFBaUM7QUFHakMsTUFBTSxLQUFLLEdBQUcsSUFBQSxlQUFRLEVBQUMsaUJBQWlCLENBQUMsQ0FBQztBQUU3QixRQUFBLHdCQUF3QixHQUFHO0lBQ3RDLEdBQUcsRUFBRSxVQUFVO0lBQ2YsSUFBSSxFQUFFLFlBQVk7Q0FDbkIsQ0FBQztBQUVGLDBGQUEwRjtBQUMxRiwwREFBMEQ7QUFDMUQsc0hBQXNIO0FBQ3RILE1BQU0sRUFBRSxHQUFHLG1CQUFRLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsa0NBQWtDLENBQUMsQ0FBQztBQUV0RSxTQUFTLFFBQVEsQ0FBQyxNQUFjO0lBQzlCLE9BQU87UUFDTCxFQUFFLEVBQUUsRUFBRTtRQUNOLEdBQUcsRUFBRSxtQkFBUSxDQUFDLEdBQUcsQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQztLQUN2QyxDQUFDO0FBQ0osQ0FBQztBQUVELFNBQWdCLGNBQWMsQ0FBQyxTQUFpQixFQUFFLE1BQWM7SUFDOUQsTUFBTSxFQUFFLEVBQUUsRUFBRSxHQUFHLEVBQUUsR0FBRyxRQUFRLENBQUMsTUFBTSxDQUFDLENBQUM7SUFDckMsTUFBTSxhQUFhLEdBQUcsbUJBQVEsQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLFNBQVMsRUFBRSxHQUFHLEVBQUUsRUFBRSxFQUFFLEVBQUUsQ0FBQyxDQUFDLFFBQVEsRUFBRSxDQUFDO0lBQzlFLE9BQU8s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