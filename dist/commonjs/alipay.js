"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AlipaySdk = exports.SSEField = exports.AlipayRequestError = void 0;
const util_1 = require("util");
const crypto_1 = require("crypto");
const stream_1 = require("stream");
const urllib_1 = __importStar(require("urllib"));
const camelcase_keys_1 = __importDefault(require("camelcase-keys"));
const snakecase_keys_1 = __importDefault(require("snakecase-keys"));
const sse_decoder_1 = require("sse-decoder");
const AlipayFormStream_js_1 = require("./AlipayFormStream.js");
const form_js_1 = require("./form.js");
const util_js_1 = require("./util.js");
const antcertutil_js_1 = require("./antcertutil.js");
const debug = (0, util_1.debuglog)('alipay-sdk');
const http2Agent = new urllib_1.Agent({
    allowH2: true,
});
class AlipayRequestError extends Error {
    code;
    traceId;
    responseHttpStatus;
    responseDataRaw;
    responseHttpHeaders;
    links;
    constructor(message, options) {
        if (options?.traceId) {
            message = `${message} (traceId: ${options.traceId})`;
        }
        super(message, options);
        this.code = options?.code;
        this.traceId = options?.traceId;
        this.responseHttpStatus = options?.responseHttpStatus;
        this.responseHttpHeaders = options?.responseHttpHeaders;
        this.responseDataRaw = options?.responseDataRaw;
        this.links = options?.links;
        this.name = this.constructor.name;
        Error.captureStackTrace(this, this.constructor);
    }
}
exports.AlipayRequestError = AlipayRequestError;
var SSEField;
(function (SSEField) {
    SSEField["EVENT"] = "event";
    SSEField["DATA"] = "data";
    SSEField["ID"] = "id";
    SSEField["RETRY"] = "retry";
})(SSEField || (exports.SSEField = SSEField = {}));
/**
 * Alipay OpenAPI SDK for Node.js
 */
class AlipaySdk {
    version = 'alipay-sdk-nodejs-4.0.0';
    config;
    #proxyAgent;
    /**
     * @class
     * @param {AlipaySdkConfig} config 初始化 SDK 配置
     */
    constructor(config) {
        if (!config.appId) {
            throw Error('config.appId is required');
        }
        if (!config.privateKey) {
            throw Error('config.privateKey is required');
        }
        // FIXME: 都使用 PRIVATE KEY 其实就够了
        const privateKeyType = config.keyType === 'PKCS8' ? 'PRIVATE KEY' : 'RSA PRIVATE KEY';
        config.privateKey = this.formatKey(config.privateKey, privateKeyType);
        // 普通公钥模式和证书模式二选其一，传入了证书路径或内容认为是证书模式
        if (config.appCertPath || config.appCertContent) {
            // 证书模式，优先处理传入了证书内容的情况，其次处理传入证书文件路径的情况
            // 应用公钥证书序列号提取
            config.appCertSn = config.appCertContent ? (0, antcertutil_js_1.getSN)(config.appCertContent, false)
                : (0, antcertutil_js_1.getSNFromPath)(config.appCertPath, false);
            // 支付宝公钥证书序列号提取
            config.alipayCertSn = config.alipayPublicCertContent ? (0, antcertutil_js_1.getSN)(config.alipayPublicCertContent, false)
                : (0, antcertutil_js_1.getSNFromPath)(config.alipayPublicCertPath, false);
            // 支付宝根证书序列号提取
            config.alipayRootCertSn = config.alipayRootCertContent ? (0, antcertutil_js_1.getSN)(config.alipayRootCertContent, true)
                : (0, antcertutil_js_1.getSNFromPath)(config.alipayRootCertPath, true);
            config.alipayPublicKey = config.alipayPublicCertContent ? (0, antcertutil_js_1.loadPublicKey)(config.alipayPublicCertContent)
                : (0, antcertutil_js_1.loadPublicKeyFromPath)(config.alipayPublicCertPath);
            config.alipayPublicKey = this.formatKey(config.alipayPublicKey, 'PUBLIC KEY');
        }
        else if (config.alipayPublicKey) {
            // 普通公钥模式，传入了支付宝公钥
            config.alipayPublicKey = this.formatKey(config.alipayPublicKey, 'PUBLIC KEY');
        }
        this.#proxyAgent = config.proxyAgent;
        this.config = Object.assign({
            urllib: urllib_1.default,
            gateway: 'https://openapi.alipay.com/gateway.do',
            endpoint: 'https://openapi.alipay.com',
            timeout: 5000,
            camelcase: true,
            signType: 'RSA2',
            charset: 'utf-8',
            version: '1.0',
        }, (0, camelcase_keys_1.default)(config, { deep: true }));
    }
    // 格式化 key
    formatKey(key, type) {
        const item = key.split('\n').map(val => val.trim());
        // 删除包含 `RSA PRIVATE KEY / PUBLIC KEY` 等字样的第一行
        if (item[0].includes(type)) {
            item.shift();
        }
        // 删除包含 `RSA PRIVATE KEY / PUBLIC KEY` 等字样的最后一行
        if (item[item.length - 1].includes(type)) {
            item.pop();
        }
        return `-----BEGIN ${type}-----\n${item.join('')}\n-----END ${type}-----`;
    }
    // 格式化请求 url（按规范把某些固定的参数放入 url）
    formatUrl(url, params) {
        const requestUrl = new URL(url);
        // 需要放在 url 中的参数列表
        const urlArgs = [
            'app_id', 'method', 'format', 'charset',
            'sign_type', 'sign', 'timestamp', 'version',
            'notify_url', 'return_url', 'auth_token', 'app_auth_token',
            'app_cert_sn', 'alipay_root_cert_sn',
            'ws_service_url',
        ];
        const execParams = {};
        for (const key in params) {
            const value = params[key];
            if (urlArgs.includes(key)) {
                // 放 URL 的参数
                requestUrl.searchParams.set(key, value);
            }
            else {
                // 放 Body 的参数
                execParams[key] = value;
            }
        }
        return { execParams, url: requestUrl.toString() };
    }
    /**
     * Alipay OpenAPI V3 with JSON Response
     * @see https://opendocs.alipay.com/open-v3/054kaq?pathHash=b3eb94e6
     */
    async curl(httpMethod, path, options) {
        return await this.#curl(httpMethod, path, options, 'json');
    }
    /**
     * Alipay OpenAPI V3 with Stream Response
     * @see https://opendocs.alipay.com/open-v3/054kaq?pathHash=b3eb94e6
     */
    async curlStream(httpMethod, path, options) {
        return await this.#curl(httpMethod, path, options, 'stream');
    }
    /**
     * Alipay OpenAPI V3 with SSE Response
     * @see https://opendocs.alipay.com/open-v3/054kaq?pathHash=b3eb94e6
     */
    async *sse(httpMethod, path, options) {
        const { stream } = await this.curlStream(httpMethod, path, options);
        const parsedStream = sse_decoder_1.Stream.fromReadableStream(stream, undefined, {
            disableJSONParse: true,
        });
        let lastEventName = '';
        for await (const line of parsedStream) {
            debug('[%s][sse] line: %o', Date.now(), line.substring(0, 100));
            // SSE 格式 https://developer.mozilla.org/zh-CN/docs/Web/API/Server-sent_events/Using_server-sent_events#%E4%BA%8B%E4%BB%B6%E6%B5%81%E6%A0%BC%E5%BC%8F
            // event: start
            // data: { ... }
            //
            // event: error
            // data: {"payload":"{\\"errorCode\\":\\"Resource-Not-Found\\",\\"errorMsg\\":\\"应用不存在\\"}","type":"error"}'
            //
            // event: end
            // data: {"type":"end"}
            if (line.startsWith(':')) {
                // ignore comment
                continue;
            }
            const index = line.indexOf(': ');
            if (index === -1)
                continue;
            const field = line.substring(0, index);
            const value = line.substring(index + 2);
            if (field === SSEField.RETRY) {
                // ignore
                continue;
            }
            if (field === SSEField.EVENT) {
                if (lastEventName) {
                    // 将上一次 event 触发
                    yield { event: lastEventName, data: '' };
                }
                lastEventName = value;
                continue;
            }
            if (field === SSEField.DATA) {
                yield { event: lastEventName, data: value };
                // 清空 event
                lastEventName = '';
            }
        }
    }
    async #curl(httpMethod, path, options, dataType = 'json') {
        httpMethod = httpMethod.toUpperCase();
        let url = `${this.config.endpoint}${path}`;
        let httpRequestUrl = path;
        let httpRequestBody = '';
        const requestOptions = {
            method: httpMethod,
            dataType: dataType === 'stream' ? 'stream' : 'text',
            timeout: options?.requestTimeout ?? this.config.timeout,
            dispatcher: this.#proxyAgent,
        };
        // 默认需要对响应做验签，确保响应是由支付宝返回的
        let validateResponseSignature = true;
        if (dataType === 'stream') {
            // 使用 HTTP/2 请求才支持流式响应
            requestOptions.dispatcher = http2Agent;
            // 流式响应不需要对响应做验签
            validateResponseSignature = false;
        }
        if (validateResponseSignature && !this.config.alipayPublicKey) {
            throw new TypeError('请确保支付宝公钥 config.alipayPublicKey 已经配置，需要使用它对响应进行验签');
        }
        // 覆盖默认配置
        if (options?.agent) {
            requestOptions.dispatcher = options.agent;
        }
        const requestId = options?.requestId ?? (0, util_js_1.createRequestId)();
        requestOptions.headers = {
            'user-agent': this.version,
            'alipay-request-id': requestId,
            accept: 'application/json',
        };
        if (options?.query) {
            const urlObject = new URL(url);
            for (const key in options.query) {
                urlObject.searchParams.set(key, String(options.query[key]));
            }
            url = urlObject.toString();
            httpRequestUrl = `${urlObject.pathname}${urlObject.search}`;
        }
        if (httpMethod === 'GET' || httpMethod === 'HEAD') {
            if (options?.body || options?.form) {
                throw new TypeError('GET / HEAD 请求不允许提交 body 或 form 数据');
            }
        }
        else {
            if (options?.form) {
                if (options.needEncrypt) {
                    throw new TypeError('提交 form 数据不支持内容加密');
                }
                // 文件上传，走 multipart/form-data
                let form;
                if (options.form instanceof form_js_1.AlipayFormData) {
                    form = new AlipayFormStream_js_1.AlipayFormStream();
                    const dataFieldValue = {};
                    for (const item of options.form.fields) {
                        dataFieldValue[item.name] = item.value;
                    }
                    if (options.body) {
                        // body 有数据也合并到 dataFieldValue 中
                        Object.assign(dataFieldValue, options.body);
                    }
                    httpRequestBody = JSON.stringify(dataFieldValue);
                    form.field('data', httpRequestBody, 'application/json');
                    // 文件上传 https://opendocs.alipay.com/open-v3/054oog#%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0
                    for (const item of options.form.files) {
                        if (item.path) {
                            form.file(item.fieldName, item.path, item.name);
                        }
                        else if (item.content) {
                            form.buffer(item.fieldName, item.content, item.name);
                        }
                        else if (item.stream) {
                            form.stream(item.fieldName, item.stream, item.name);
                        }
                    }
                }
                else if (options.form instanceof AlipayFormStream_js_1.AlipayFormStream) {
                    form = options.form;
                    if (options.body) {
                        // body 有数据设置到 dataFieldValue 中
                        httpRequestBody = JSON.stringify(options.body);
                        form.field('data', httpRequestBody, 'application/json');
                    }
                }
                else {
                    throw new TypeError('options.form 必须是 AlipayFormData 或者 AlipayFormStream 类型');
                }
                requestOptions.content = new stream_1.Readable().wrap(form);
                Object.assign(requestOptions.headers, form.headers());
            }
            else {
                // 普通请求
                let contentType = 'application/json';
                httpRequestBody = options?.body ? JSON.stringify(options.body) : '';
                if (options?.needEncrypt) {
                    if (!this.config.encryptKey) {
                        throw new TypeError('请配置 config.encryptKey 才能通过 needEncrypt = true 进行请求内容加密调用');
                    }
                    // 加密请求
                    contentType = 'text/plain';
                    // 目前只支持 AES
                    requestOptions.headers['alipay-encryption-algm'] = 'AES';
                    requestOptions.headers['alipay-encrypt-type'] = 'AES';
                    httpRequestBody = (0, util_js_1.aesEncryptText)(httpRequestBody, this.config.encryptKey);
                }
                requestOptions.headers['content-type'] = contentType;
                requestOptions.content = httpRequestBody;
            }
        }
        if (this.config.alipayRootCertSn) {
            requestOptions.headers['alipay-root-cert-sn'] = this.config.alipayRootCertSn;
        }
        // 签名规则 https://opendocs.alipay.com/open-v3/054q58?pathHash=474929ac#%E6%99%AE%E9%80%9A%E8%AF%B7%E6%B1%82
        // authString 拼接格式：
        //
        // ```txt
        // app_id=${app_id},app_cert_sn=${app_cert_sn},nonce=${nonce},timestamp=${timestamp}
        // ```
        let authString = `app_id=${this.config.appId}`;
        if (this.config.appCertSn) {
            authString += `,app_cert_sn=${this.config.appCertSn}`;
        }
        authString += `,nonce=${(0, crypto_1.randomUUID)()},timestamp=${Date.now()}`;
        // 签名字符串拼接格式：
        //
        // ```txt
        // ${authString}\n
        // ${httpMethod}\n
        // ${httpRequestUrl}\n
        // ${httpRequestBody}\n
        // ${appAuthToken}\n
        // ```
        let signString = `${authString}\n${httpMethod}\n${httpRequestUrl}\n${httpRequestBody}\n`;
        if (options?.appAuthToken) {
            requestOptions.headers['alipay-app-auth-token'] = options.appAuthToken;
            signString += `${options.appAuthToken}\n`;
        }
        const signature = (0, util_js_1.signatureV3)(signString, this.config.privateKey);
        const authorization = `ALIPAY-SHA256withRSA ${authString},sign=${signature}`;
        debug('signString: \n--------\n%s\n--------\nauthorization: %o', signString, authorization);
        requestOptions.headers.authorization = authorization;
        debug('curl %s %s, with body: %s, headers: %j, dataType: %s', httpMethod, url, httpRequestBody, requestOptions.headers, dataType);
        let httpResponse;
        try {
            httpResponse = await urllib_1.default.request(url, requestOptions);
        }
        catch (err) {
            debug('HttpClient Request error: %s', err.message);
            debug(err);
            throw new AlipayRequestError(`HttpClient Request error, ${err.message}`, {
                cause: err,
                traceId: requestId,
            });
        }
        const traceId = httpResponse.headers['alipay-trace-id'] ?? requestId;
        debug('curl response status: %s, headers: %j, raw text body: %s, traceId: %s', httpResponse.status, httpResponse.headers, httpResponse.data, traceId);
        // 错误码封装 https://opendocs.alipay.com/open-v3/054fcv?pathHash=7bdeefa1
        if (httpResponse.status >= 400) {
            let errorData;
            if (dataType === 'stream') {
                // 需要手动反序列化 JSON 数据
                const bytes = await (0, util_js_1.readableToBytes)(httpResponse.res);
                errorData = JSON.parse(bytes.toString());
                debug('stream to errorData: %j', errorData);
            }
            else {
                errorData = JSON.parse(httpResponse.data);
            }
            throw new AlipayRequestError(errorData.message, {
                code: errorData.code,
                links: errorData.links,
                responseHttpStatus: httpResponse.status,
                responseHttpHeaders: httpResponse.headers,
                traceId,
            });
        }
        if (dataType === 'stream') {
            // 流式响应 OpenAI 不会加密，不需要处理
            return {
                stream: httpResponse.res,
                responseHttpStatus: httpResponse.status,
                traceId,
            };
        }
        let httpResponseBody = httpResponse.data;
        // 对支付宝响应进行验签 https://opendocs.alipay.com/open-v3/054d0z?pathHash=dcad8d5c
        if (validateResponseSignature) {
            const headers = httpResponse.headers;
            const responseSignString = `${headers['alipay-timestamp']}\n${headers['alipay-nonce']}\n${httpResponseBody}\n`;
            const expectedSignature = headers['alipay-signature'];
            const expectedAlipaySN = headers['alipay-sn'];
            if (expectedAlipaySN && this.config.alipayCertSn && expectedAlipaySN !== this.config.alipayCertSn) {
                throw new AlipayRequestError(`支付宝公钥证书号不匹配，服务端返回的是：${expectedAlipaySN}，SDK 配置的是：${this.config.alipayCertSn}`, {
                    code: 'response-alipay-sn-verify-error',
                    responseDataRaw: httpResponse.data,
                    responseHttpStatus: httpResponse.status,
                    responseHttpHeaders: httpResponse.headers,
                    traceId,
                });
            }
            debug('responseSignString: \n--------\n%s\n--------\nexpectedSignature: %o', responseSignString, expectedSignature);
            if (!(0, util_js_1.verifySignatureV3)(responseSignString, expectedSignature, this.config.alipayPublicKey)) {
                throw new AlipayRequestError(`支付宝响应验签失败，请确保支付宝公钥 config.alipayPublicKey 是最新有效版本，签名字符串为：${expectedSignature}，验证字符串为：${JSON.stringify(responseSignString)}`, {
                    code: 'response-signature-verify-error',
                    responseDataRaw: httpResponse.data,
                    responseHttpStatus: httpResponse.status,
                    responseHttpHeaders: httpResponse.headers,
                    traceId,
                });
            }
        }
        if (options?.needEncrypt) {
            httpResponseBody = this.aesDecrypt(httpResponseBody);
            if (!httpResponseBody) {
                throw new AlipayRequestError('解密失败，请确认 config.encryptKey 设置正确', {
                    code: 'decrypt-error',
                    responseDataRaw: httpResponse.data,
                    responseHttpStatus: httpResponse.status,
                    responseHttpHeaders: httpResponse.headers,
                    traceId,
                });
            }
        }
        return {
            data: JSON.parse(httpResponseBody),
            responseHttpStatus: httpResponse.status,
            traceId,
        };
    }
    // 文件上传
    async #multipartExec(method, options) {
        const config = this.config;
        let signParams = {};
        let formData = {};
        options.formData.getFields().forEach(field => {
            // formData 的字段类型应为 string。（兼容 null）
            const parsedFieldValue = typeof field.value === 'object' && field.value ?
                JSON.stringify(field.value) : field.value;
            // 字段加入签名参数（文件不需要签名）
            signParams[field.name] = parsedFieldValue;
            formData[field.name] = parsedFieldValue;
        });
        // 签名方法中使用的 key 是驼峰
        signParams = (0, camelcase_keys_1.default)(signParams, { deep: true });
        formData = (0, snakecase_keys_1.default)(formData);
        const formStream = new AlipayFormStream_js_1.AlipayFormStream();
        for (const k in formData) {
            formStream.field(k, formData[k]);
        }
        options.formData.getFiles().forEach(file => {
            // 文件名需要转换驼峰为下划线
            const fileKey = (0, util_js_1.decamelize)(file.fieldName);
            // 单独处理文件类型
            if (file.path) {
                formStream.file(fileKey, file.path, file.name);
            }
            else if (file.stream) {
                formStream.stream(fileKey, file.stream, file.name);
            }
            else if (file.content) {
                formStream.buffer(fileKey, file.content, file.name);
            }
        });
        const requestOptions = {
            method: 'POST',
            dataType: 'text',
            timeout: config.timeout,
            headers: {
                'user-agent': this.version,
                accept: 'application/json',
                ...formStream.headers(),
            },
            content: new stream_1.Readable().wrap(formStream),
            dispatcher: this.#proxyAgent,
        };
        // 计算签名
        const signData = (0, util_js_1.sign)(method, signParams, config);
        // 格式化 url
        const { url } = this.formatUrl(config.gateway, signData);
        options.log?.info('[AlipaySdk] start exec url: %s, method: %s, params: %j', url, method, signParams);
        let httpResponse;
        try {
            httpResponse = await urllib_1.default.request(url, requestOptions);
        }
        catch (err) {
            debug('HttpClient Request error: %s', err);
            throw new AlipayRequestError(`HttpClient Request error: ${err.message}`, {
                cause: err,
            });
        }
        return this.#formatExecHttpResponse(method, httpResponse, {
            validateSign: options.validateSign,
        });
    }
    /**
     * 生成请求字符串，用于客户端进行调用
     * @param {string} method 方法名
     * @param {IRequestParams} bizParams 请求参数
     * @param {object} bizParams.bizContent 业务请求参数
     * @return {string} 请求字符串
     */
    sdkExecute(method, bizParams, options) {
        if (options?.bizContentAutoSnakeCase !== false) {
            bizParams = (0, camelcase_keys_1.default)(bizParams, { deep: true });
        }
        const data = (0, util_js_1.sign)(method, bizParams, this.config, {
            bizContentAutoSnakeCase: options?.bizContentAutoSnakeCase,
        });
        const sdkStr = Object.keys(data).map(key => {
            return `${key}=${encodeURIComponent(data[key])}`;
        }).join('&');
        return sdkStr;
    }
    /**
     * @alias sdkExecute
     */
    sdkExec(method, bizParams) {
        return this.sdkExecute(method, bizParams);
    }
    pageExecute(method, httpMethodOrParams, bizParams) {
        const formData = new form_js_1.AlipayFormData();
        let httpMethod = '';
        if (typeof httpMethodOrParams === 'string') {
            httpMethod = httpMethodOrParams;
        }
        else if (typeof httpMethodOrParams === 'object') {
            bizParams = httpMethodOrParams;
        }
        if (!httpMethod && bizParams?.method) {
            httpMethod = bizParams.method;
        }
        for (const k in bizParams) {
            if (k === 'method')
                continue;
            formData.addField(k, bizParams[k]);
        }
        if (httpMethod) {
            formData.setMethod(httpMethod);
        }
        return this.#pageExec(method, { formData });
    }
    pageExec(method, httpMethodOrParams, bizParams) {
        if (bizParams) {
            return this.pageExecute(method, httpMethodOrParams, bizParams);
        }
        return this.pageExecute(method, httpMethodOrParams);
    }
    // page 类接口，兼容原来的 formData 格式
    #pageExec(method, option = {}) {
        let signParams = { alipaySdk: this.version };
        const config = this.config;
        option.formData.getFields().forEach(field => {
            signParams[field.name] = field.value;
        });
        // 签名方法中使用的 key 是驼峰
        signParams = (0, camelcase_keys_1.default)(signParams, { deep: true });
        // 计算签名，并返回标准化的请求字段（含 bizContent stringify）
        const signData = (0, util_js_1.sign)(method, signParams, config);
        // 格式化 url
        const { url, execParams } = this.formatUrl(config.gateway, signData);
        option.log?.info('[AlipaySdk]start exec url: %s, method: %s, params: %s', url, method, JSON.stringify(signParams));
        if (option.formData.getMethod() === 'get') {
            const query = Object.keys(execParams).map(key => {
                return `${key}=${encodeURIComponent(execParams[key])}`;
            });
            return `${url}&${query.join('&')}`;
        }
        const formName = `alipaySDKSubmit${Date.now()}`;
        return (`
      <form action="${url}" method="post" name="${formName}" id="${formName}">
        ${Object.keys(execParams).map(key => {
            const value = String(execParams[key]).replace(/\"/g, '&quot;');
            return `<input type="hidden" name="${key}" value="${value}" />`;
        }).join('')}
      </form>
      <script>document.forms["${formName}"].submit();</script>
    `);
    }
    // 消息验签
    notifyRSACheck(signArgs, signStr, signType, raw) {
        const signContent = Object.keys(signArgs).sort().filter(val => val)
            .map(key => {
            let value = signArgs[key];
            if (Array.prototype.toString.call(value) !== '[object String]') {
                value = JSON.stringify(value);
            }
            // 如果 value 中包含了诸如 % 字符，decodeURIComponent 会报错
            // 而且 notify 消息大部分都是 post 请求，无需进行 decodeURIComponent 操作
            if (raw) {
                return `${key}=${value}`;
            }
            return `${key}=${decodeURIComponent(value)}`;
        })
            .join('&');
        return this.rsaCheck(signContent, signStr, signType);
    }
    /**
     * @ignore
     * @param originStr 开放平台返回的原始字符串
     * @param responseKey xx_response 方法名 key
     */
    getSignStr(originStr, responseKey) {
        // 待签名的字符串
        let validateStr = originStr.trim();
        // 找到 xxx_response 开始的位置
        const startIndex = originStr.indexOf(`${responseKey}"`);
        // 找到最后一个 “"sign"” 字符串的位置（避免）
        const lastIndex = originStr.lastIndexOf('"sign"');
        /**
         * 删除 xxx_response 及之前的字符串
         * 假设原始字符串为
         *  {"xxx_response":{"code":"10000"},"sign":"jumSvxTKwn24G5sAIN"}
         * 删除后变为
         *  :{"code":"10000"},"sign":"jumSvxTKwn24G5sAIN"}
         */
        validateStr = validateStr.substring(startIndex + responseKey.length + 1);
        /**
         * 删除最后一个 "sign" 及之后的字符串
         * 删除后变为
         *  :{"code":"10000"},
         * {} 之间就是待验签的字符串
         */
        validateStr = validateStr.substring(0, lastIndex);
        // 删除第一个 { 之前的任何字符
        validateStr = validateStr.replace(/^[^{]*{/g, '{');
        // 删除最后一个 } 之后的任何字符
        validateStr = validateStr.replace(/\}([^}]*)$/g, '}');
        return validateStr;
    }
    /**
     * 执行请求，调用支付宝服务端
     * @param {string} method 调用接口方法名，比如 alipay.ebpp.bill.add
     * @param {IRequestParams} params 请求参数
     * @param {object} params.bizContent 业务请求参数
     * @param {IRequestOption} options 选项
     * @param {Boolean} options.validateSign 是否验签
     * @param {Console} options.log 可选日志记录对象
     * @return {Promise<AlipaySdkCommonResult | string>} 请求执行结果
     */
    async exec(method, params = {}, options = {}) {
        if (options.formData) {
            if (options.formData.getFiles().length > 0) {
                return await this.#multipartExec(method, options);
            }
            /**
             * fromData 中不包含文件时，认为是 page 类接口（返回 form 表单）
             * 比如 PC 端支付接口 alipay.trade.page.pay
             */
            throw new TypeError('formData 参数不包含文件，你可能是希望获取 POST 表单 HTML，请调用 pageExec() 方法代替');
        }
        const config = this.config;
        // 计算签名
        const signParams = (0, util_js_1.sign)(method, params, config);
        const { url, execParams } = this.formatUrl(config.gateway, signParams);
        debug('start exec, url: %s, method: %s, params: %o', url, method, execParams);
        let httpResponse;
        try {
            httpResponse = await urllib_1.default.request(url, {
                method: 'POST',
                data: execParams,
                // 按 text 返回（为了验签）
                dataType: 'text',
                timeout: config.timeout,
                headers: {
                    'user-agent': this.version,
                    'alipay-request-id': options.traceId ?? (0, util_js_1.createRequestId)(),
                    // 请求须设置 HTTP 头部： Content-Type: application/json, Accept: application/json
                    // 加密请求和文件上传 API 除外。
                    // 'content-type': 'application/json',
                    accept: 'application/json',
                },
                dispatcher: this.#proxyAgent,
            });
        }
        catch (err) {
            debug('HttpClient Request error: %s', err);
            throw new AlipayRequestError(`HttpClient Request error: ${err.message}`, {
                cause: err,
            });
        }
        return this.#formatExecHttpResponse(method, httpResponse, {
            needEncrypt: params.needEncrypt,
            validateSign: options.validateSign,
        });
    }
    #formatExecHttpResponse(method, httpResponse, options) {
        debug('http response status: %s, headers: %j, raw text: %o', httpResponse.status, httpResponse.headers, httpResponse.data);
        const traceId = httpResponse.headers.trace_id;
        if (httpResponse.status !== 200) {
            throw new AlipayRequestError(`HTTP 请求错误, status: ${httpResponse.status}`, {
                traceId,
                responseDataRaw: httpResponse.data,
            });
        }
        /**
         * 示例响应格式
         * {"alipay_trade_precreate_response":
         *  {"code": "10000","msg": "Success","out_trade_no": "111111","qr_code": "https:\/\/"},
         *  "sign": "abcde="
         * }
         * 或者
         * {"error_response":
         *  {"code":"40002","msg":"Invalid Arguments","sub_code":"isv.code-invalid","sub_msg":"授权码code无效"},
         * }
         * {
         *   "alipay_security_risk_content_analyze_response": {
         *     "code":"40002",
         *     "msg":"Invalid Arguments",
         *     "sub_code":"isv.invalid-signature",
         *     "sub_msg":"验签出错，建议检查签名字符串或签名私钥与应用公钥是否匹配，网关生成的验签字符串为：app_id=2021000122671080&amp;charset=utf-8&amp;method=alipay.security.risk.content.analyze&amp;sign_type=RSA2&amp;timestamp=2024-05-13 17:49:20&amp;version=1.0"
         *   },
         *   "sign":"GJpcj4/ylSq1tK1G2AWOKJwC/RudLpjANiT2LMYRRY7Aveb0xj2N4Hi1hoIctB+8vusl9qdfFGZZUpReMsnbz19twzvPEYXE6EPZmd00hymmVTch5SFceEU/sb6WY0Fae/EDr51lR5XurUWsxeOHMz/MiiiJsQT0c8lZlpxOEZ9gA6urN4mSfxMKksryCVb9seZhqmBMAGoLg+MMlrUQqstichteg2qdwFMq5pPFzoTmgDcmMsBspjsLR8Wy/b65Z/wNrsXc0OiWSVfP4d0O/J0lD4RrzdJ2zuV6PVWvGrPx/76DajnFYvzWNDeogfFWNA2b4LWByIFCQ0E3yEdOZQ=="
         * }
         */
        let alipayResponse;
        try {
            alipayResponse = JSON.parse(httpResponse.data);
        }
        catch (err) {
            throw new AlipayRequestError('Response 格式错误', {
                traceId,
                responseDataRaw: httpResponse.data,
                cause: err,
            });
        }
        const responseKey = `${method.replaceAll('.', '_')}_response`;
        let data = alipayResponse[responseKey] ?? alipayResponse.error_response;
        if (data) {
            if (options?.needEncrypt) {
                if (typeof data === 'string') {
                    data = (0, util_js_1.aesDecrypt)(data, this.config.encryptKey);
                }
                else {
                    // 服务端解密错误，"sub_msg":"解密出错, 未知错误"
                    // ignore
                }
            }
            // 按字符串验签
            if (options?.validateSign) {
                const serverSign = alipayResponse.sign;
                this.checkResponseSign(httpResponse.data, responseKey, serverSign, traceId);
            }
            const result = this.config.camelcase ? (0, camelcase_keys_1.default)(data, { deep: true }) : data;
            if (result && traceId) {
                result.traceId = traceId;
            }
            return result;
        }
        throw new AlipayRequestError(`Response 格式错误，返回值 ${responseKey} 找不到`, {
            traceId,
            responseDataRaw: httpResponse.data,
        });
    }
    // 结果验签
    checkResponseSign(responseDataRaw, responseKey, serverSign, traceId) {
        if (!this.config.alipayPublicKey) {
            console.warn('[alipay-sdk] config.alipayPublicKey is empty, skip validateSign');
            // 支付宝公钥不存在时不做验签
            return;
        }
        // 带验签的参数不存在时返回失败
        if (!responseDataRaw) {
            throw new AlipayRequestError('验签失败，服务端返回值为空无法进行验签', {
                traceId,
                responseDataRaw,
            });
        }
        // 根据服务端返回的结果截取需要验签的目标字符串
        const validateStr = this.getSignStr(responseDataRaw, responseKey);
        // 参数存在，并且是正常的结果（不包含 sub_code）时才验签
        const verifier = (0, crypto_1.createVerify)(util_js_1.ALIPAY_ALGORITHM_MAPPING[this.config.signType]);
        verifier.update(validateStr, 'utf8');
        const success = verifier.verify(this.config.alipayPublicKey, serverSign, 'base64');
        if (!success) {
            throw new AlipayRequestError(`验签失败，服务端返回的 sign: '${serverSign}' 无效, validateStr: '${validateStr}'`, {
                traceId,
                responseDataRaw,
            });
        }
    }
    /**
     * 通知验签，不对 value 进行 decode
     * @param {JSON} postData 服务端的消息内容
     * @return { Boolean } 验签是否成功
     */
    checkNotifySignV2(postData) {
        // 修复常见问题 https://github.com/alipay/alipay-sdk-nodejs-all/issues/45
        // 由于要保持 checkNotifySign 方法兼容性，所以新增一个 checkNotifySignV2 代替
        return this.checkNotifySign(postData, true);
    }
    /**
     * 通知验签
     * @param {JSON} postData 服务端的消息内容
     * @param {Boolean} raw 是否使用 raw 内容而非 decode 内容验签
     * @return { Boolean } 验签是否成功
     */
    checkNotifySign(postData, raw) {
        const signStr = postData.sign;
        // 未设置“支付宝公钥”或签名字符串不存，验签不通过
        if (!this.config.alipayPublicKey || !signStr) {
            return false;
        }
        // 先从签名字符串中取 sign_type，再取配置项、都不存在时默认为 RSA2（RSA 已不再推荐使用）
        const signType = postData.sign_type || this.config.signType || 'RSA2';
        const signArgs = { ...postData };
        // 除去 sign
        delete signArgs.sign;
        /**
         * 某些用户可能自己删除了 sign_type 后再验签
         * 为了保持兼容性临时把 sign_type 加回来
         * 因为下面的逻辑会验签 2 次所以不会存在验签不同过的情况
         */
        signArgs.sign_type = signType;
        // 保留 sign_type 验证一次签名
        const verifyResult = this.notifyRSACheck(signArgs, signStr, signType, raw);
        if (!verifyResult) {
            /**
             * 删除 sign_type 验一次
             * 因为“历史原因”需要用户自己判断是否需要保留 sign_type 验证签名
             * 这里是把其他 sdk 中的 rsaCheckV1、rsaCheckV2 做了合并
             */
            delete signArgs.sign_type;
            return this.notifyRSACheck(signArgs, signStr, signType, raw);
        }
        return true;
    }
    /**
     * 对加密内容进行 AES 解密
     * @see https://opendocs.alipay.com/common/02mse3#AES%20%E8%A7%A3%E5%AF%86%E5%87%BD%E6%95%B0
     * @param encryptedText 加密内容字符串
     */
    aesDecrypt(encryptedText) {
        return (0, util_js_1.aesDecryptText)(encryptedText, this.config.encryptKey);
    }
    /**
     * 对指定内容进行验签
     *
     * 如对前端返回的报文进行验签 https://opendocs.alipay.com/common/02mse3#AES%20%E8%A7%A3%E5%AF%86%E5%87%BD%E6%95%B0
     */
    rsaCheck(signContent, sign, signType = 'RSA2') {
        const verifier = (0, crypto_1.createVerify)(util_js_1.ALIPAY_ALGORITHM_MAPPING[signType]);
        return verifier.update(signContent, 'utf-8').verify(this.config.alipayPublicKey, sign, 'base64');
    }
}
exports.AlipaySdk = AlipaySdk;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYWxpcGF5LmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL2FsaXBheS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFBQSwrQkFBZ0M7QUFDaEMsbUNBQWtEO0FBQ2xELG1DQUFrQztBQUNsQyxpREFBNEQ7QUFLNUQsb0VBQTJDO0FBQzNDLG9FQUEyQztBQUMzQyw2Q0FBa0Q7QUFDbEQsK0RBQXlEO0FBRXpELHVDQUEyQztBQUMzQyx1Q0FLbUI7QUFDbkIscURBQThGO0FBRTlGLE1BQU0sS0FBSyxHQUFHLElBQUEsZUFBUSxFQUFDLFlBQVksQ0FBQyxDQUFDO0FBQ3JDLE1BQU0sVUFBVSxHQUFHLElBQUksY0FBSyxDQUFDO0lBQzNCLE9BQU8sRUFBRSxJQUFJO0NBQ2QsQ0FBQyxDQUFDO0FBcUJILE1BQWEsa0JBQW1CLFNBQVEsS0FBSztJQUMzQyxJQUFJLENBQVU7SUFDZCxPQUFPLENBQVU7SUFDakIsa0JBQWtCLENBQVU7SUFDNUIsZUFBZSxDQUFVO0lBQ3pCLG1CQUFtQixDQUF1QjtJQUMxQyxLQUFLLENBQW1DO0lBRXhDLFlBQVksT0FBZSxFQUFFLE9BQW1DO1FBQzlELElBQUksT0FBTyxFQUFFLE9BQU8sRUFBRSxDQUFDO1lBQ3JCLE9BQU8sR0FBRyxHQUFHLE9BQU8sY0FBYyxPQUFPLENBQUMsT0FBTyxHQUFHLENBQUM7UUFDdkQsQ0FBQztRQUNELEtBQUssQ0FBQyxPQUFPLEVBQUUsT0FBTyxDQUFDLENBQUM7UUFDeEIsSUFBSSxDQUFDLElBQUksR0FBRyxPQUFPLEVBQUUsSUFBSSxDQUFDO1FBQzFCLElBQUksQ0FBQyxPQUFPLEdBQUcsT0FBTyxFQUFFLE9BQU8sQ0FBQztRQUNoQyxJQUFJLENBQUMsa0JBQWtCLEdBQUcsT0FBTyxFQUFFLGtCQUFrQixDQUFDO1FBQ3RELElBQUksQ0FBQyxtQkFBbUIsR0FBRyxPQUFPLEVBQUUsbUJBQW1CLENBQUM7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