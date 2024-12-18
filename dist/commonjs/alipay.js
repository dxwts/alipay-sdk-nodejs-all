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
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYWxpcGF5LmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL2FsaXBheS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBLCtCQUFnQztBQUNoQyxtQ0FBa0Q7QUFDbEQsbUNBQWtDO0FBQ2xDLGlEQUE0RDtBQUs1RCxvRUFBMkM7QUFDM0Msb0VBQTJDO0FBQzNDLDZDQUFrRDtBQUNsRCwrREFBeUQ7QUFFekQsdUNBQTJDO0FBQzNDLHVDQUttQjtBQUNuQixxREFBOEY7QUFFOUYsTUFBTSxLQUFLLEdBQUcsSUFBQSxlQUFRLEVBQUMsWUFBWSxDQUFDLENBQUM7QUFDckMsTUFBTSxVQUFVLEdBQUcsSUFBSSxjQUFLLENBQUM7SUFDM0IsT0FBTyxFQUFFLElBQUk7Q0FDZCxDQUFDLENBQUM7QUFxQkgsTUFBYSxrQkFBbUIsU0FBUSxLQUFLO0lBQzNDLElBQUksQ0FBVTtJQUNkLE9BQU8sQ0FBVTtJQUNqQixrQkFBa0IsQ0FBVTtJQUM1QixlQUFlLENBQVU7SUFDekIsbUJBQW1CLENBQXVCO0lBQzFDLEtBQUssQ0FBbUM7SUFFeEMsWUFBWSxPQUFlLEVBQUUsT0FBbUM7UUFDOUQsSUFBSSxPQUFPLEVBQUUsT0FBTyxFQUFFLENBQUM7WUFDckIsT0FBTyxHQUFHLEdBQUcsT0FBTyxjQUFjLE9BQU8sQ0FBQyxPQUFPLEdBQUcsQ0FBQztRQUN2RCxDQUFDO1FBQ0QsS0FBSyxDQUFDLE9BQU8sRUFBRSxPQUFPLENBQUMsQ0FBQztRQUN4QixJQUFJLENBQUMsSUFBSSxHQUFHLE9BQU8sRUFBRSxJQUFJLENBQUM7UUFDMUIsSUFBSSxDQUFDLE9BQU8sR0FBRyxPQUFPLEVBQUUsT0FBTyxDQUFDO1FBQ2hDLElBQUksQ0FBQyxrQkFBa0IsR0FBRyxPQUFPLEVBQUUsa0JBQWtCLENBQUM7UUFDdEQsSUFBSSxDQUFDLG1CQUFtQixHQUFHLE9BQU8sRUFBRSxtQkFBbUIsQ0FBQztRQUN4RCxJQUFJ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