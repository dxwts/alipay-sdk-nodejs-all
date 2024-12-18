"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getSN = exports.getSNFromPath = exports.loadPublicKey = exports.loadPublicKeyFromPath = void 0;
const fs_1 = __importDefault(require("fs"));
const crypto_1 = require("crypto");
const bignumber_js_1 = require("bignumber.js");
const x509_1 = require("@fidm/x509");
/** 从公钥证书文件里读取支付宝公钥 */
function loadPublicKeyFromPath(filePath) {
    const fileData = fs_1.default.readFileSync(filePath);
    const certificate = x509_1.Certificate.fromPEM(fileData);
    return certificate.publicKeyRaw.toString('base64');
}
exports.loadPublicKeyFromPath = loadPublicKeyFromPath;
/** 从公钥证书内容或 Buffer 读取支付宝公钥 */
function loadPublicKey(content) {
    const pemContent = typeof content === 'string' ? Buffer.from(content) : content;
    const certificate = x509_1.Certificate.fromPEM(pemContent);
    return certificate.publicKeyRaw.toString('base64');
}
exports.loadPublicKey = loadPublicKey;
/** 从证书文件里读取序列号 */
function getSNFromPath(filePath, isRoot = false) {
    const fileData = fs_1.default.readFileSync(filePath);
    return getSN(fileData, isRoot);
}
exports.getSNFromPath = getSNFromPath;
/** 从上传的证书内容或 Buffer 读取序列号 */
function getSN(fileData, isRoot = false) {
    const pemData = typeof fileData === 'string' ? Buffer.from(fileData) : fileData;
    if (isRoot) {
        return getRootCertSN(pemData);
    }
    const certificate = x509_1.Certificate.fromPEM(pemData);
    return getCertSN(certificate);
}
exports.getSN = getSN;
/** 读取序列号 */
function getCertSN(certificate) {
    const { issuer, serialNumber } = certificate;
    const principalName = issuer.attributes
        .reduceRight((prev, curr) => {
        const { shortName, value } = curr;
        const result = `${prev}${shortName}=${value},`;
        return result;
    }, '')
        .slice(0, -1);
    const decimalNumber = new bignumber_js_1.BigNumber(serialNumber, 16).toString(10);
    const SN = (0, crypto_1.createHash)('md5')
        .update(principalName + decimalNumber, 'utf8')
        .digest('hex');
    return SN;
}
/** 读取根证书序列号 */
function getRootCertSN(rootContent) {
    const certificates = x509_1.Certificate.fromPEMs(rootContent);
    let rootCertSN = '';
    certificates.forEach(item => {
        if (item.signatureOID.startsWith('1.2.840.113549.1.1')) {
            const SN = getCertSN(item);
            if (rootCertSN.length === 0) {
                rootCertSN += SN;
            }
            else {
                rootCertSN += `_${SN}`;
            }
        }
    });
    return rootCertSN;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYW50Y2VydHV0aWwuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvYW50Y2VydHV0aWwudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7O0FBQUEsNENBQW9CO0FBQ3BCLG1DQUFvQztBQUNwQywrQ0FBeUM7QUFDekMscUNBQXlDO0FBRXpDLHNCQUFzQjtBQUN0QixTQUFnQixxQkFBcUIsQ0FBQyxRQUFnQjtJQUNwRCxNQUFNLFFBQVEsR0FBRyxZQUFFLENBQUMsWUFBWSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0lBQzNDLE1BQU0sV0FBVyxHQUFHLGtCQUFXLENBQUMsT0FBTyxDQUFDLFFBQVEsQ0FBQyxDQUFDO0lBQ2xELE9BQU8sV0FBVyxDQUFDLFlBQVksQ0FBQyxRQUFRLENBQUMsUUFBUSxDQUFDLENBQUM7QUFDckQsQ0FBQztBQUpELHNEQUlDO0FBRUQsOEJBQThCO0FBQzlCLFNBQWdCLGFBQWEsQ0FBQyxPQUF3QjtJQUNwRCxNQUFNLFVBQVUsR0FBRyxPQUFPLE9BQU8sS0FBSyxRQUFRLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQztJQUNoRixNQUFNLFdBQVcsR0FBRyxrQkFBVyxDQUFDLE9BQU8sQ0FBQyxVQUFVLENBQUMsQ0FBQztJQUNwRCxPQUFPLFdBQVcsQ0FBQyxZQUFZLENBQUMsUUFBUSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0FBQ3JELENBQUM7QUFKRCxzQ0FJQztBQUVELGtCQUFrQjtBQUNsQixTQUFnQixhQUFhLENBQUMsUUFBZ0IsRUFBRSxNQUFNLEdBQUcsS0FBSztJQUM1RCxNQUFNLFFBQVEsR0FBRyxZQUFFLENBQUMsWUFBWSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0lBQzNDLE9BQU8sS0FBSyxDQUFDLFFBQVEsRUFBRSxNQUFNLENBQUMsQ0FBQztBQUNqQyxDQUFDO0FBSEQsc0NBR0M7QUFFRCw2QkFBNkI7QUFDN0IsU0FBZ0IsS0FBSyxDQUFDLFFBQXlCLEVBQUUsTUFBTSxHQUFHLEtBQUs7SUFDN0QsTUFBTSxPQUFPLEdBQUcsT0FBTyxRQUFRLEtBQUssUUFBUSxDQUFDLENBQUMsQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFDLENBQUMsQ0FBQyxRQUFRLENBQUM7SUFDaEYsSUFBSSxNQUFNLEVBQUUsQ0FBQztRQUNYLE9BQU8sYUFBYSxDQUFDLE9BQU8sQ0FBQyxDQUFDO0lBQ2hDLENBQUM7SUFDRCxNQUFNLFdBQVcsR0FBRyxrQkFBVyxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUMsQ0FBQztJQUNqRCxPQUFPLFNBQVMsQ0FBQyxXQUFXLENBQUMsQ0FBQztBQUNoQyxDQUFDO0FBUEQsc0JBT0M7QUFFRCxZQUFZO0FBQ1osU0FBUyxTQUFTLENBQUMsV0FBd0I7SUFDekMsTUFBTSxFQUFFLE1BQU0sRUFBRSxZQUFZLEVBQUUsR0FBRyxXQUFXLENBQUM7SUFDN0MsTUFBTSxhQUFhLEdBQUcsTUFBTSxDQUFDLFVBQVU7U0FDcEMsV0FBVyxDQUFDLENBQUMsSUFBSSxFQUFFLElBQUksRUFBRSxFQUFFO1FBQzFCLE1BQU0sRUFBRSxTQUFTLEVBQUUsS0FBSyxFQUFFLEdBQUcsSUFBSSxDQUFDO1FBQ2xDLE1BQU0sTUFBTSxHQUFHLEdBQUcsSUFBSSxHQUFHLFNBQVMsSUFBSSxLQUFLLEdBQUcsQ0FBQztRQUMvQyxPQUFPLE1BQU0sQ0FBQztJQUNoQixDQUFDLEVBQUUsRUFBRSxDQUFDO1NBQ0wsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQ2hCLE1BQU0sYUFBYSxHQUFHLElBQUksd0JBQVMsQ0FBQyxZQUFZLEVBQUUsRUFBRSxDQUFDLENBQUMsUUFBUSxDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBQ25FLE1BQU0sRUFBRSxHQUFHLElBQUEsbUJBQVUsRUFBQyxLQUFLLENBQUM7U0FDekIsTUFBTSxDQUFDLGFBQWEsR0FBRyxhQUFhLEVBQUUsTUFBTSxDQUFDO1NBQzdDLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQztJQUNqQixPQUFPLEVBQUUsQ0FBQztBQUNaLENBQUM7QUFFRCxlQUFlO0FBQ2YsU0FBUyxhQUFhLENBQUMsV0FBbUI7SUFDeEMsTUFBTSxZQUFZLEdBQUcsa0JBQVcsQ0FBQyxRQUFRLENBQUMsV0FBVyxDQUFDLENBQUM7SUFDdkQsSUFBSSxVQUFVLEdBQUcsRUFBRSxDQUFDO0lBQ3BCLFlBQVksQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDLEVBQUU7UUFDMUIsSUFBSSxJQUFJLENBQUMsWUFBWSxDQUFDLFVBQVUsQ0FBQyxvQkFBb0IsQ0FBQyxFQUFFLENBQUM7WUFDdkQsTUFBTSxFQUFFLEdBQUcsU0FBUyxDQUFDLElBQUksQ0FBQyxDQUFDO1lBQzNCLElBQUksVUFBVSxDQUFDLE1BQU0sS0FBSyxDQUFDLEVBQUUsQ0FBQztnQkFDNUIsVUFBVSxJQUFJLEVBQUUsQ0FBQztZQUNuQixDQUFDO2lCQUFNLENBQUM7Z0JBQ04sVUFBVSxJQUFJLElBQUksRUFBRSxFQUFFLENBQUM7WUFDekIsQ0FBQztRQUNILENBQUM7SUFDSCxDQUFDLENBQUMsQ0FBQztJQUNILE9BQU8sVUFBVSxDQUFDO0FBQ3BCLENBQUMifQ==