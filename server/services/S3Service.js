const { PutObjectCommand } = require('@aws-sdk/client-s3');
const s3 = require('../infra/aws/s3');

const upload = async (file, key, mimetype) => {
  const bucket = process.env.S3_BUCKET;
  const region = process.env.S3_REGION;
  const params = {
    Bucket: bucket,
    ContentType: mimetype,
    Key: key,
    Body: file,
  };

  const command = new PutObjectCommand(params);
  await s3.send(command);

  // LOCAL: when IMAGE_READ_BASE is set, return a read URL served through the shared gateway
  // (<base>/<bucket>/<key>, e.g. http://localhost:8088/s3/...), which the browser can resolve.
  // Unset in production, so the returned URL stays the public AWS virtual-host S3 URL.
  const readBase = process.env.IMAGE_READ_BASE;
  return readBase
    ? `${readBase}/${bucket}/${encodeURIComponent(key)}`
    : `https://${bucket}.s3.${region}.amazonaws.com/${encodeURIComponent(key)}`;
};

module.exports = {
  upload,
};
