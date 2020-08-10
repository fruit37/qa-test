const crypto = require('crypto')
const nodeRSA = require('node-rsa')
const keythereum = require('keythereum')
const web3Utils = require('web3-utils')
const APIKEY_SECRET_LENGTH = 256
const APIKEY_SEED_LENGTH = 256

const createHash = (secret, apiKey) => {
    const hmac = crypto.createHmac('sha256', apiKey)
    return hmac.update(secret).digest('hex')
}
const createSha1Digest = message => {
    const sha1 = crypto.createHash('sha1')
    return sha1.update(message).digest('hex')
}
const createSha256Digest = message => {
    const sha256 = crypto.createHash('sha256')
    return sha256.update(message).digest('hex')
}
const _randomString = () => Math.random().toString(36).substring(2, 10)
const createRandomString = function (len) {
    const loop = Math.ceil(len / 8) + 1
    return Array(loop).fill(0).map(_randomString).join("").substr(0, len)
}
const createSecret = () => createRandomString(APIKEY_SECRET_LENGTH)
const createApiKey = () => {
    const secret = createSecret()
    const seed = createRandomString(APIKEY_SEED_LENGTH)
    const apiKey = createSha1Digest(seed)
    const hash = createHash(secret, apiKey)
    
    return {
        apiKey,
        hash,
        secret
    }
}
const checkApiKey = (secret, apiKey, hash) => {
    const _hash = createHash(secret, apiKey)
    return _hash === hash
}
const createApiKeyID = apiKey => createSha1Digest(apiKey)

const createRSAKeyPairs = () => {
    const key = new nodeRSA({b: 2048})
    const privateKey = key.exportKey('pkcs1-private-pem')
    const publicKey = key.exportKey('pkcs1-public-pem')
    return {
        privateKey,
        publicKey
    }
}
const createRSAKeyID = pubKey => createSha1Digest(pubKey)
const encryptRSA = (text, priKey) => {
    const key = new nodeRSA()
    key.importKey(priKey, 'pkcs1-private-pem')
    return key.encryptPrivate(text, 'base64')
}
const decryptRSA = (encrypted, pubKey) => {
    const key = new nodeRSA()
    key.importKey(pubKey, 'pkcs1-public-pem')
    return key.decryptPublic(encrypted, 'utf8')
}
const signRSA = (text, priKey) => {
    const key = new nodeRSA()
    key.importKey(priKey, 'pkcs1-private-pem')
    return key.sign(text, 'hex', 'utf8')
}
const verifyRSA = (text, sig, pubKey) => {
    const key = new nodeRSA()
    key.importKey(pubKey, 'pkcs1-public-pem')
    return key.verify(text, sig, 'utf8', 'hex')
}
const checkEncryptionKey = (encryptionKeyID, encryptionKey) => {
    const _encryptionKeyID = createRSAKeyID(encryptionKey)
    return _encryptionKeyID === encryptionKeyID
}
const decryptEthPrivateKey = (encrypted, password) => {
    const ks = JSON.parse(encrypted)
    const privateKey = keythereum.recover(password, ks).toString('hex')
    const address = keythereum.privateKeyToAddress(privateKey)
    return {
        privateKey,
        address: web3Utils.toChecksumAddress(address)
    }
}
const createAssetAccountID = (pubKey, address) => createSha1Digest(pubKey + address) 
const checkAssetAccount = (assetAccountID, AssetAccountPubKey, assetAccountAddress) => {
    const _assetAccountID = createRSAKeyID(AssetAccountPubKey + assetAccountAddress)
    return _assetAccountID === assetAccountID
}

module.exports = {
    createHash,
    createRandomString,
    createSecret,
    createSha1Digest,
    createSha256Digest,
    createApiKey,
    checkApiKey,
    createApiKeyID,
    createRSAKeyPairs,
    createRSAKeyID,
    encryptRSA,
    decryptRSA,
    signRSA,
    verifyRSA,
    checkEncryptionKey,
    decryptEthPrivateKey,
    createAssetAccountID,
    checkAssetAccount
}
