import { debuglog } from 'util';
import { createVerify, randomUUID } from 'crypto';
import { Readable } from 'stream';
import urllib, { Agent } from 'urllib';
import camelcaseKeys from 'camelcase-keys';
import snakeCaseKeys from 'snakecase-keys';
import { Stream as SSEStream } from 'sse-decoder';
import { AlipayFormStream } from './AlipayFormStream.js';
import { AlipayFormData } from './form.js';
import { sign, ALIPAY_ALGORITHM_MAPPING, decamelize, createRequestId, readableToBytes, aesDecrypt, aesEncryptText, aesDecryptText, signatureV3, verifySignatureV3, } from './util.js';
import { getSNFromPath, getSN, loadPublicKey, loadPublicKeyFromPath } from './antcertutil.js';
const debug = debuglog('alipay-sdk');
const http2Agent = new Agent({
    allowH2: true,
});
export class AlipayRequestError extends Error {
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
export var SSEField;
(function (SSEField) {
    SSEField["EVENT"] = "event";
    SSEField["DATA"] = "data";
    SSEField["ID"] = "id";
    SSEField["RETRY"] = "retry";
})(SSEField || (SSEField = {}));
/**
 * Alipay OpenAPI SDK for Node.js
 */
export class AlipaySdk {
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
            config.appCertSn = config.appCertContent ? getSN(config.appCertContent, false)
                : getSNFromPath(config.appCertPath, false);
            // 支付宝公钥证书序列号提取
            config.alipayCertSn = config.alipayPublicCertContent ? getSN(config.alipayPublicCertContent, false)
                : getSNFromPath(config.alipayPublicCertPath, false);
            // 支付宝根证书序列号提取
            config.alipayRootCertSn = config.alipayRootCertContent ? getSN(config.alipayRootCertContent, true)
                : getSNFromPath(config.alipayRootCertPath, true);
            config.alipayPublicKey = config.alipayPublicCertContent ? loadPublicKey(config.alipayPublicCertContent)
                : loadPublicKeyFromPath(config.alipayPublicCertPath);
            config.alipayPublicKey = this.formatKey(config.alipayPublicKey, 'PUBLIC KEY');
        }
        else if (config.alipayPublicKey) {
            // 普通公钥模式，传入了支付宝公钥
            config.alipayPublicKey = this.formatKey(config.alipayPublicKey, 'PUBLIC KEY');
        }
        this.#proxyAgent = config.proxyAgent;
        this.config = Object.assign({
            urllib,
            gateway: 'https://openapi.alipay.com/gateway.do',
            endpoint: 'https://openapi.alipay.com',
            timeout: 5000,
            camelcase: true,
            signType: 'RSA2',
            charset: 'utf-8',
            version: '1.0',
        }, camelcaseKeys(config, { deep: true }));
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
        const parsedStream = SSEStream.fromReadableStream(stream, undefined, {
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
        const requestId = options?.requestId ?? createRequestId();
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
                if (options.form instanceof AlipayFormData) {
                    form = new AlipayFormStream();
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
                else if (options.form instanceof AlipayFormStream) {
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
                requestOptions.content = new Readable().wrap(form);
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
                    httpRequestBody = aesEncryptText(httpRequestBody, this.config.encryptKey);
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
        authString += `,nonce=${randomUUID()},timestamp=${Date.now()}`;
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
        const signature = signatureV3(signString, this.config.privateKey);
        const authorization = `ALIPAY-SHA256withRSA ${authString},sign=${signature}`;
        debug('signString: \n--------\n%s\n--------\nauthorization: %o', signString, authorization);
        requestOptions.headers.authorization = authorization;
        debug('curl %s %s, with body: %s, headers: %j, dataType: %s', httpMethod, url, httpRequestBody, requestOptions.headers, dataType);
        let httpResponse;
        try {
            httpResponse = await urllib.request(url, requestOptions);
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
                const bytes = await readableToBytes(httpResponse.res);
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
            if (!verifySignatureV3(responseSignString, expectedSignature, this.config.alipayPublicKey)) {
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
        signParams = camelcaseKeys(signParams, { deep: true });
        formData = snakeCaseKeys(formData);
        const formStream = new AlipayFormStream();
        for (const k in formData) {
            formStream.field(k, formData[k]);
        }
        options.formData.getFiles().forEach(file => {
            // 文件名需要转换驼峰为下划线
            const fileKey = decamelize(file.fieldName);
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
            content: new Readable().wrap(formStream),
            dispatcher: this.#proxyAgent,
        };
        // 计算签名
        const signData = sign(method, signParams, config);
        // 格式化 url
        const { url } = this.formatUrl(config.gateway, signData);
        options.log?.info('[AlipaySdk] start exec url: %s, method: %s, params: %j', url, method, signParams);
        let httpResponse;
        try {
            httpResponse = await urllib.request(url, requestOptions);
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
            bizParams = camelcaseKeys(bizParams, { deep: true });
        }
        const data = sign(method, bizParams, this.config, {
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
        const formData = new AlipayFormData();
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
        signParams = camelcaseKeys(signParams, { deep: true });
        // 计算签名，并返回标准化的请求字段（含 bizContent stringify）
        const signData = sign(method, signParams, config);
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
        const signParams = sign(method, params, config);
        const { url, execParams } = this.formatUrl(config.gateway, signParams);
        debug('start exec, url: %s, method: %s, params: %o', url, method, execParams);
        let httpResponse;
        try {
            httpResponse = await urllib.request(url, {
                method: 'POST',
                data: execParams,
                // 按 text 返回（为了验签）
                dataType: 'text',
                timeout: config.timeout,
                headers: {
                    'user-agent': this.version,
                    'alipay-request-id': options.traceId ?? createRequestId(),
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
                    data = aesDecrypt(data, this.config.encryptKey);
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
            const result = this.config.camelcase ? camelcaseKeys(data, { deep: true }) : data;
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
        const verifier = createVerify(ALIPAY_ALGORITHM_MAPPING[this.config.signType]);
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
        return aesDecryptText(encryptedText, this.config.encryptKey);
    }
    /**
     * 对指定内容进行验签
     *
     * 如对前端返回的报文进行验签 https://opendocs.alipay.com/common/02mse3#AES%20%E8%A7%A3%E5%AF%86%E5%87%BD%E6%95%B0
     */
    rsaCheck(signContent, sign, signType = 'RSA2') {
        const verifier = createVerify(ALIPAY_ALGORITHM_MAPPING[signType]);
        return verifier.update(signContent, 'utf-8').verify(this.config.alipayPublicKey, sign, 'base64');
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYWxpcGF5LmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL2FsaXBheS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxPQUFPLEVBQUUsUUFBUSxFQUFFLE1BQU0sTUFBTSxDQUFDO0FBQ2hDLE9BQU8sRUFBRSxZQUFZLEVBQUUsVUFBVSxFQUFFLE1BQU0sUUFBUSxDQUFDO0FBQ2xELE9BQU8sRUFBRSxRQUFRLEVBQUUsTUFBTSxRQUFRLENBQUM7QUFDbEMsT0FBTyxNQUFNLEVBQUUsRUFBRSxLQUFLLEVBQXVCLE1BQU0sUUFBUSxDQUFDO0FBSzVELE9BQU8sYUFBYSxNQUFNLGdCQUFnQixDQUFDO0FBQzNDLE9BQU8sYUFBYSxNQUFNLGdCQUFnQixDQUFDO0FBQzNDLE9BQU8sRUFBRSxNQUFNLElBQUksU0FBUyxFQUFFLE1BQU0sYUFBYSxDQUFDO0FBQ2xELE9BQU8sRUFBRSxnQkFBZ0IsRUFBRSxNQUFNLHVCQUF1QixDQUFDO0FBRXpELE9BQU8sRUFBRSxjQUFjLEVBQUUsTUFBTSxXQUFXLENBQUM7QUFDM0MsT0FBTyxFQUNMLElBQUksRUFBRSx3QkFBd0IsRUFBRSxVQUFVLEVBQUUsZUFBZSxFQUFFLGVBQWUsRUFDNUUsVUFBVSxFQUFFLGNBQWMsRUFDMUIsY0FBYyxFQUNkLFdBQVcsRUFBRSxpQkFBaUIsR0FDL0IsTUFBTSxXQUFXLENBQUM7QUFDbkIsT0FBTyxFQUFFLGFBQWEsRUFBRSxLQUFLLEVBQUUsYUFBYSxFQUFFLHFCQUFxQixFQUFFLE1BQU0sa0JBQWtCLENBQUM7QUFFOUYsTUFBTSxLQUFLLEdBQUcsUUFBUSxDQUFDLFlBQVksQ0FBQyxDQUFDO0FBQ3JDLE1BQU0sVUFBVSxHQUFHLElBQUksS0FBSyxDQUFDO0lBQzNCLE9BQU8sRUFBRSxJQUFJO0NBQ2QsQ0FBQyxDQUFDO0FBcUJILE1BQU0sT0FBTyxrQkFBbUIsU0FBUSxLQUFLO0lBQzNDLElBQUksQ0FBVTtJQUNkLE9BQU8sQ0FBVTtJQUNqQixrQkFBa0Is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