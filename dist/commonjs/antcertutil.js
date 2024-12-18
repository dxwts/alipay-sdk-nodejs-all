"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.loadPublicKeyFromPath = loadPublicKeyFromPath;
exports.loadPublicKey = loadPublicKey;
exports.getSNFromPath = getSNFromPath;
exports.getSN = getSN;
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
/** 从公钥证书内容或 Buffer 读取支付宝公钥 */
function loadPublicKey(content) {
    const pemContent = typeof content === 'string' ? Buffer.from(content) : content;
    const certificate = x509_1.Certificate.fromPEM(pemContent);
    return certificate.publicKeyRaw.toString('base64');
}
/** 从证书文件里读取序列号 */
function getSNFromPath(filePath, isRoot = false) {
    const fileData = fs_1.default.readFileSync(filePath);
    return getSN(fileData, isRoot);
}
/** 从上传的证书内容或 Buffer 读取序列号 */
function getSN(fileData, isRoot = false) {
    const pemData = typeof fileData === 'string' ? Buffer.from(fileData) : fileData;
    if (isRoot) {
        return getRootCertSN(pemData);
    }
    const certificate = x509_1.Certificate.fromPEM(pemData);
    return getCertSN(certificate);
}
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYW50Y2VydHV0aWwuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvYW50Y2VydHV0aWwudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7QUFNQSxzREFJQztBQUdELHNDQUlDO0FBR0Qsc0NBR0M7QUFHRCxzQkFPQztBQWpDRCw0Q0FBb0I7QUFDcEIsbUNBQW9DO0FBQ3BDLCtDQUF5QztBQUN6QyxxQ0FBeUM7QUFFekMsc0JBQXNCO0FBQ3RCLFNBQWdCLHFCQUFxQixDQUFDLFFBQWdCO0lBQ3BELE1BQU0sUUFBUSxHQUFHLFlBQUUsQ0FBQyxZQUFZLENBQUMsUUFBUSxDQUFDLENBQUM7SUFDM0MsTUFBTSxXQUFXLEdBQUcsa0JBQVcsQ0FBQyxPQUFPLENBQUMsUUFBUSxDQUFDLENBQUM7SUFDbEQsT0FBTyxXQUFXLENBQUMsWUFBWSxDQUFDLFFBQVEsQ0FBQyxRQUFRLENBQUMsQ0FBQztBQUNyRCxDQUFDO0FBRUQsOEJBQThCO0FBQzlCLFNBQWdCLGFBQWEsQ0FBQyxPQUF3QjtJQUNwRCxNQUFNLFVBQVUsR0FBRyxPQUFPLE9BQU8sS0FBSyxRQUFRLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQztJQUNoRixNQUFNLFdBQVcsR0FBRyxrQkFBVyxDQUFDLE9BQU8sQ0FBQyxVQUFVLENBQUMsQ0FBQztJQUNwRCxPQUFPLFdBQVcsQ0FBQyxZQUFZLENBQUMsUUFBUSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0FBQ3JELENBQUM7QUFFRCxrQkFBa0I7QUFDbEIsU0FBZ0IsYUFBYSxDQUFDLFFBQWdCLEVBQUUsTUFBTSxHQUFHLEtBQUs7SUFDNUQsTUFBTSxRQUFRLEdBQUcsWUFBRSxDQUFDLFlBQVksQ0FBQyxRQUFRLENBQUMsQ0FBQztJQUMzQyxPQUFPLEtBQUssQ0FBQyxRQUFRLEVBQUUsTUFBTSxDQUFDLENBQUM7QUFDakMsQ0FBQztBQUVELDZCQUE2QjtBQUM3QixTQUFnQixLQUFLLENBQUMsUUFBeUIsRUFBRSxNQUFNLEdBQUcsS0FBSztJQUM3RCxNQUFNLE9BQU8sR0FBRyxPQUFPLFFBQVEsS0FBSyxRQUFRLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQyxDQUFDLFFBQVEsQ0FBQztJQUNoRixJQUFJLE1BQU0sRUFBRSxDQUFDO1FBQ1gsT0FBTyxhQUFhLENBQUMsT0FBTyxDQUFDLENBQUM7SUFDaEMsQ0FBQztJQUNELE1BQU0sV0FBVyxHQUFHLGtCQUFXLENBQUMsT0FBTyxDQUFDLE9BQU8sQ0FBQyxDQUFDO0lBQ2pELE9BQU8sU0FBUyxDQUFDLFdBQVcsQ0FBQyxDQUFDO0FBQ2hDLENBQUM7QUFFRCxZQUFZO0FBQ1osU0FBUyxTQUFTLENBQUMsV0FBd0I7SUFDekMsTUFBTSxFQUFFLE1BQU0sRUFBRSxZQUFZLEVBQUUsR0FBRyxXQUFXLENBQUM7SUFDN0MsTUFBTSxhQUFhLEdBQUcsTUFBTSxDQUFDLFVBQVU7U0FDcEMsV0FBVyxDQUFDLENBQUMsSUFBSSxFQUFFLElBQUksRUFBRSxFQUFFO1FBQzFCLE1BQU0sRUFBRSxTQUFTLEVBQUUsS0FBSyxFQUFFLEdBQUcsSUFBSSxDQUFDO1FBQ2xDLE1BQU0sTUFBTSxHQUFHLEdBQUcsSUFBSSxHQUFHLFNBQVMsSUFBSSxLQUFLLEdBQUcsQ0FBQztRQUMvQyxPQUFPLE1BQU0sQ0FBQztJQUNoQixDQUFDLEVBQUUsRUFBRSxDQUFDO1NBQ0wsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQ2hCLE1BQU0sYUFBYSxHQUFHLElBQUksd0JBQVMsQ0FBQyxZQUFZLEVBQUUsRUFBRSxDQUFDLENBQUMsUUFBUSxDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBQ25FLE1BQU0sRUFBRSxHQUFHLElBQUEsbUJBQVUsRUFBQyxLQUFLLENBQUM7U0FDekIsTUFBTSxDQUFDLGFBQWEsR0FBRyxhQUFhLEVBQUUsTUFBTSxDQUFDO1NBQzdDLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQztJQUNqQixPQUFPLEVBQUUsQ0FBQztBQUNaLENBQUM7QUFFRCxlQUFlO0FBQ2YsU0FBUyxhQUFhLENBQUMsV0FBbUI7SUFDeEMsTUFBTSxZQUFZLEdBQUcsa0JBQVcsQ0FBQyxRQUFRLENBQUMsV0FBVyxDQUFDLENBQUM7SUFDdkQsSUFBSSxVQUFVLEdBQUcsRUFBRSxDQUFDO0lBQ3BCLFlBQVksQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDLEVBQUU7UUFDMUIsSUFBSSxJQUFJLENBQUMsWUFBWSxDQUFDLFVBQVUsQ0FBQyxvQkFBb0IsQ0FBQyxFQUFFLENBQUM7WUFDdkQsTUFBTSxFQUFFLEdBQUcsU0FBUyxDQUFDLElBQUksQ0FBQyxDQUFDO1lBQzNCLElBQUksVUFBVSxDQUFDLE1BQU0sS0FBSyxDQUFDLEVBQUUsQ0FBQztnQkFDNUIsVUFBVSxJQUFJLEVBQUUsQ0FBQztZQUNuQixDQUFDO2lCQUFNLENBQUM7Z0JBQ04sVUFBVSxJQUFJLElBQUksRUFBRSxFQUFFLENBQUM7WUFDekIsQ0FBQztRQUNILENBQUM7SUFDSCxDQUFDLENBQUMsQ0FBQztJQUNILE9BQU8sVUFBVSxDQUFDO0FBQ3BCLENBQUMifQ==