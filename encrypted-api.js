"use strict";

(function(root)
{
	/*
	 * Initialization
	 */

	var encryptedApi = function(secret1, secret2, error_handler)
	{
		if (!(this instanceof encryptedApi))
			throw Error('encryptedApi must be instanitated with `new`');

		this.signature_length = 64;
		this.iv_length = 16;
		this.id_length = 32;
		this.shared_secret_minimum_length = 32;
		this.error_handler = error_handler;

		var nodejsroot = require('window-or-global');

		this.crypto = nodejsroot.crypto || nodejsroot.msCrypto;

		if (!this.crypto)
			return this.reportError('encryptedApi: no suitable crypto implementation found.');

		this.aesjs = require('aes-js');
		this.jssha = require('jssha');
		this.ajax = require('ajax-request');
		this.secret1 = this.aesjs.utils.utf8.toBytes(secret1);
		this.secret2 = this.aesjs.utils.utf8.toBytes(secret2);
		this.requests = new Array();
	}

	/*
	 * API call execution
	 */

	encryptedApi.prototype.executeCall = function(url, method, callback, data)
	{
		if (typeof data !== 'undefined' && typeof data !== 'object' && typeof data !== 'string')
			return this.reportError('EncryptedApi executeCall data must be an object or a string.');

		if (this.checkSharedSecrets())
			return;

		var id = this.generateRequestId();
		var iv = this.generateIv();

		this.requests[id] = true;

		var data = {
			'id': id,
			'timestamp': Math.floor(Date.now() / 1000),
			'data': typeof data === 'undefined' ? {} : data,
			'url': url,
			'method': method.toLowerCase(),
			'headers': null,
		};

		data = JSON.stringify(data);

		var secret1 = this.secret1.slice(0, this.shared_secret_minimum_length);
		var aesCtr = new this.aesjs.ModeOfOperation.ctr(secret1, new this.aesjs.Counter(this.aesjs.utils.hex.toBytes(iv)));
		var encryptedData = this.aesjs.utils.hex.fromBytes(aesCtr.encrypt(this.aesjs.utils.utf8.toBytes(data)));

		var sha512 = new this.jssha('SHA-512', 'TEXT');
		sha512.setHMACKey(this.secret2, 'ARRAYBUFFER');
		sha512.update(encryptedData + iv);

		data = {
			'data': encryptedData,
			'iv': iv,
			'signature': sha512.getHMAC('HEX'),
		};

		this.checkDataFormat(data.data);
		this.checkIvFormat(data.iv);
		this.checkSignatureFormat(data.signature);

		var request = {
			'url': url,
			'method': method.toUpperCase(),
			'data': data,
			'encoding': 'utf-8',
			'headers': {
				'Accept': 'application/json',
			},
		};

		if (method.toLowerCase() == 'get') {
			request.method = 'POST';
			request.headers = {
				'Accept': 'application/json',
				'X-HTTP-Method-Override': 'GET',
			};
		}

		var self = this;
		this.ajax(request, function(error, response, body) {
			if (error)
				return self.reportError('encryptedApi request failed: ' + error);

			if (!response)
				return self.reportError('encryptedApi received no response from endpoint: ' + url);

			if (response.headers['content-type'] !== 'application/json')
				return self.reportError('encryptedApi response is not JSON, returned Content-Type: ' + response.headers['content-type'] + ', returned body: ' + body);

			var json = self.parseJSON(body);
			if (!json.data || !json.iv || !json.signature)
				return self.reportError('encryptedApi response JSON is not in expected format: ' + body);

			self.checkDataFormat(json.data);
			self.checkIvFormat(json.iv);
			self.checkSignatureFormat(json.signature);

			var sha512 = new self.jssha('SHA-512', 'TEXT');
			sha512.setHMACKey(self.secret2, 'ARRAYBUFFER');
			sha512.update(json.data + json.iv);
			var signature = sha512.getHMAC('HEX');

			if (signature !== json.signature)
				return self.reportError('encryptedApi response signature is invalid, expected ' + signature + ', got ' + json.signature);

			var secret1 = self.secret1.slice(0, self.shared_secret_minimum_length);
			var aesCtr = new self.aesjs.ModeOfOperation.ctr(secret1, new self.aesjs.Counter(self.aesjs.utils.hex.toBytes(json.iv)));
			var decryptedJson = self.parseJSON(self.aesjs.utils.utf8.fromBytes(aesCtr.decrypt(self.aesjs.utils.hex.toBytes(json.data))));

			if (!decryptedJson.id || !decryptedJson.timestamp || !decryptedJson.data || !decryptedJson.headers)
				return self.reportError('encryptedApi decrypted JSON is not in expected format: ' + JSON.stringify(decryptedJson));

			if (!(decryptedJson.id in self.requests))
				return self.reportError('enryptedApi received unknown request id: ' + id);

			if (parseInt(decryptedJson.timestamp) < Math.floor(Date.now() / 1000) - 10)
				return self.reportError('encryptedApi response timestamp invalid: ' + decryptedJson.timestamp);

			if (callback instanceof Function)
				callback(decryptedJson.data, decryptedJson);

			delete self.requests[decryptedJson.id];
		});
	}

	encryptedApi.prototype.generateRequestId = function()
	{
		return this.aesjs.utils.hex.fromBytes(this.generateRandomBytes(this.id_length));
	}

	encryptedApi.prototype.generateIv = function()
	{
		return this.aesjs.utils.hex.fromBytes(this.generateRandomBytes(this.iv_length));
	}

	encryptedApi.prototype.generateRandomBytes = function(length)
	{
		var bytes = new Uint8Array(length);
		this.crypto.getRandomValues(bytes);

		return bytes;
	}

	/*
	 * Sanity check functions
	 */

	encryptedApi.prototype.checkDataFormat = function(data)
	{
		return this.checkBinHexFormat(data);
	}

	encryptedApi.prototype.checkIvFormat = function(iv)
	{
		return this.checkBinHexFormat(iv, this.iv_length * 2);
	}

	encryptedApi.prototype.checkSignatureFormat = function(signature)
	{
		return this.checkBinHexFormat(signature, this.signature_length * 2);
	}

	encryptedApi.prototype.checkIdFormat = function(id)
	{
		return this.checkBinHexFormat(id, this.id_length * 2);
	}

	encryptedApi.prototype.checkSharedSecrets = function()
	{
		if (this.secret1.length < this.shared_secret_minimum_length || this.secret2.length < this.shared_secret_minimum_length)
			return this.reportError('EncryptedApi shared secrets must be at least ' + this.shared_secret_minimum_length + ' bytes long.');

		if (this.arraysAreEqual(this.secret1, this.secret2))
			return this.reportError('EncryptedApi shared secrets must not be equal to each other.');

		if (this.arraysAreEqual(this.secret1.slice(0, this.shared_secret_minimum_length), this.secret2.slice(0, this.shared_secret_minimum_length)))
			return this.reportError('EncryptedApi shared secrets first 32 bytes must not be equal to each other.');
	}

	/*
	 * Helper functions
	 */

	encryptedApi.prototype.checkBinHexFormat = function(value, length)
	{
		if (value.match(new RegExp('^[\\da-f]' + (typeof length !== 'undefined' ? '{' + parseInt(length) + '}' : '+') + '$')) === null)
			return this.reportError('EncryptedApi invalid BinHex format or invalid length.');
	}

	encryptedApi.prototype.arraysAreEqual = function(arr1, arr2)
	{
		if(arr1.length !== arr2.length)
			return false;

		for(var i = arr1.length; i--;)
			if(arr1[i] !== arr2[i])
				return false;

		return true;
	}

	encryptedApi.prototype.reportError = function(message)
	{
		if (this.error_handler instanceof Function) {
			this.error_handler(message);
			return true;
		}

		throw Error(message);
	}

	encryptedApi.prototype.parseJSON = function(json)
	{
		var result;

		try {
			result = JSON.parse(json);
		} catch (error) {
			return this.reportError('JSON parsing failed: ' + error.message);
		}

		return result;
	}

	if (typeof exports !== 'undefined') // node.js
		module.exports = encryptedApi;
	else if (typeof(define) === 'function' && define.amd) // RequireJS / AMD
		define(encryptedApi);
	else // web browsers
		root.encryptedApi = encryptedApi;
})(this);
