const fs = require('fs');
const path = require('path');

// 存储适配器基类
class StorageAdapter {
  constructor(type, config = {}) {
    this.type = type || 'local';
    this.config = config;
  }

  static create(type, config = {}) {
    switch (type) {
      case 's3':
        return new S3Storage(config);
      case 'oss':
        return new OSSStorage(config);
      default:
        return new LocalStorage(config);
    }
  }

  async upload(key, fileBuffer, options = {}) {
    throw new Error('未实现的上传方法');
  }

  async download(key) {
    throw new Error('未实现的下载方法');
  }

  async delete(key) {
    throw new Error('未实现的删除方法');
  }

  getUrl(key, expiresInSeconds = 0) {
    return this.buildUrl(key);
  }

  buildUrl(key) {
    return `${this.config.endpoint}/${key}`;
  }
}

// 本地存储
class LocalStorage extends StorageAdapter {
  constructor(config = {}) {
    super('local', config);
    this.basePath = config.basePath || './uploads';
    fs.mkdirSync(this.basePath, { recursive: true });
  }

  async upload(key, buffer) {
    const filePath = path.join(this.basePath, key);
    const dir = path.dirname(filePath);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(filePath, buffer);
    return { key, url: `/uploads/${key}`, size: buffer.length };
  }

  async download(key) {
    const filePath = path.join(this.basePath, key);
    return fs.readFileSync(filePath);
  }

  async delete(key) {
    const filePath = path.join(this.basePath, key);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  }
}

// AWS S3 存储
class S3Storage extends StorageAdapter {
  constructor(config = {}) {
    super('s3', config);
    this.bucket = config.bucket;
    this.region = config.region || 'us-east-1';
  }

  async upload(key, buffer) {
    const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
    const client = new S3Client({
      region: this.region,
      credentials: {
        accessKeyId: this.config.accessKeyId,
        secretAccessKey: this.config.secretAccessKey
      }
    });
    
    await client.send(new PutObjectCommand({
      Bucket: this.bucket,
      Key: key,
      Body: buffer
    }));
    
    return { 
      key, 
      url: `https://${this.bucket}.s3.${this.region}.amazonaws.com/${key}`,
      size: buffer.length 
    };
  }

  async download(key) {
    const { S3Client, GetObjectCommand } = require('@aws-sdk/client-s3');
    const client = new S3Client({
      region: this.region,
      credentials: {
        accessKeyId: this.config.accessKeyId,
        secretAccessKey: this.config.secretAccessKey
      }
    });
    
    const response = await client.send(new GetObjectCommand({
      Bucket: this.bucket,
      Key: key
    }));
    return response.Body;
  }

  async delete(key) {
    const { S3Client, DeleteObjectCommand } = require('@aws-sdk/client-s3');
    const client = new S3Client({
      region: this.region,
      credentials: {
        accessKeyId: this.config.accessKeyId,
        secretAccessKey: this.config.secretAccessKey
      }
    });
    
    await client.send(new DeleteObjectCommand({
      Bucket: this.bucket,
      Key: key
    }));
  }
}

// 阿里云 OSS 存储
class OSSStorage extends StorageAdapter {
  constructor(config = {}) {
    super('oss', config);
    this.bucket = config.bucket;
    this.region = config.region;
  }

  async upload(key, buffer) {
    const OSS = require('ali-oss');
    const client = new OSS({
      region: this.region,
      accessKeyId: this.config.accessKeyId,
      accessKeySecret: this.config.secretAccessKey,
      bucket: this.bucket
    });
    
    const result = await client.put(key, buffer);
    return { key, url: result.url, size: buffer.length };
  }

  async download(key) {
    const OSS = require('ali-oss');
    const client = new OSS({
      region: this.region,
      accessKeyId: this.config.accessKeyId,
      accessKeySecret: this.config.secretAccessKey,
      bucket: this.bucket
    });
    
    const result = await client.get(key);
    return result.content;
  }

  async delete(key) {
    const OSS = require('ali-oss');
    const client = new OSS({
      region: this.region,
      accessKeyId: this.config.accessKeyId,
      accessKeySecret: this.config.secretAccessKey,
      bucket: this.bucket
    });
    
    await client.delete(key);
  }
}

// 导出类和工厂方法
module.exports = StorageAdapter;
module.exports.StorageAdapter = StorageAdapter;
module.exports.LocalStorage = LocalStorage;
module.exports.S3Storage = S3Storage;
module.exports.OSSStorage = OSSStorage;
