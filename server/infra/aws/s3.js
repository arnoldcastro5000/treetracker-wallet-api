const { S3Client } = require('@aws-sdk/client-s3');

// LOCAL: when S3_ENDPOINT is set (e.g. a LocalStack URL) point the client at it and use path-style
// addressing, so buckets resolve as <endpoint>/<bucket>/<key> instead of a virtual-host AWS URL.
// Unset in production, so the client keeps its default AWS endpoint and virtual-host addressing.
const s3 = new S3Client({
  credentials: {
    accessKeyId: process.env.S3_ACCESS_KEY_ID,
    secretAccessKey: process.env.S3_SECRET_ACCESS_KEY,
  },
  region: process.env.S3_REGION,
  ...(process.env.S3_ENDPOINT
    ? { endpoint: process.env.S3_ENDPOINT, forcePathStyle: true }
    : {}),
});

module.exports = s3;
