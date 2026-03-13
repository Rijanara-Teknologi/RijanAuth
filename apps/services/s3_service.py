# -*- encoding: utf-8 -*-
"""
Pusat layanan upload, stream, dan download media dari S3 Object Storage.
Mendukung S3 AWS, MinIO, IDCloudHost, dan compatible endpoint.
"""
import boto3
import requests
import hashlib
import hmac
import os
from datetime import datetime
from urllib.parse import quote, urlparse
from botocore.exceptions import ClientError
from botocore.config import Config as BotoConfig
from typing import BinaryIO, Optional, Union


class S3Service:
    def __init__(
        self,
        endpoint_url: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        region: Optional[str] = None,
        bucket: Optional[str] = None,
    ):
        self.endpoint_url = (
            endpoint_url
            or os.environ.get('S3_ENDPOINT_URL', 'https://s3.amazonaws.com')
        ).rstrip('/')
        self.access_key = access_key or os.environ.get('S3_ACCESS_KEY_ID', '')
        self.secret_key = secret_key or os.environ.get('S3_SECRET_ACCESS_KEY', '')
        self.region = region or os.environ.get('S3_REGION', 'us-east-1')
        self.bucket = bucket or os.environ.get('S3_BUCKET_NAME', '')

        # Parse endpoint untuk host
        parsed = urlparse(self.endpoint_url)
        self.host = parsed.netloc
        self.scheme = parsed.scheme

        # Boto3 client untuk operasi yang kompatibel (download, delete, presigned URL)
        boto_config = BotoConfig(
            signature_version='s3v4',
            s3={'addressing_style': 'path'}
        )
        self.s3 = boto3.client(
            's3',
            endpoint_url=self.endpoint_url,
            aws_access_key_id=self.access_key or None,
            aws_secret_access_key=self.secret_key or None,
            region_name=self.region,
            config=boto_config
        )

    def _sign(self, key: bytes, msg: str) -> bytes:
        """HMAC-SHA256 signing."""
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def _get_signature_key(self, date_stamp: str) -> bytes:
        """Generate AWS4 signing key."""
        k_date = self._sign(('AWS4' + self.secret_key).encode('utf-8'), date_stamp)
        k_region = self._sign(k_date, self.region)
        k_service = self._sign(k_region, 's3')
        k_signing = self._sign(k_service, 'aws4_request')
        return k_signing

    def _validate_key(self, key: str) -> str:
        """Validasi dan sanitize S3 key untuk keamanan."""
        if not key or not isinstance(key, str):
            raise ValueError("Key tidak boleh kosong")

        # Hapus leading/trailing slashes dan whitespace
        key = key.strip().strip('/')

        # Cegah key menjadi kosong setelah sanitasi
        if not key:
            raise ValueError("Key tidak boleh kosong setelah sanitasi")

        # Cegah path traversal
        if '..' in key:
            raise ValueError("Key tidak valid: path traversal tidak diizinkan")

        # Cegah karakter berbahaya
        forbidden_chars = ['\\', '\x00', '\n', '\r']
        for char in forbidden_chars:
            if char in key:
                raise ValueError("Key mengandung karakter tidak valid")

        return key

    def upload_file(
        self,
        file_obj: Union[BinaryIO, bytes, str],
        key: str,
        content_type: Optional[str] = None,
        public: bool = False,
    ) -> str:
        """
        Upload file ke S3 menggunakan AWS4 signature (kompatibel dengan IDCloudHost).

        Args:
            file_obj: File object, bytes, atau string
            key: S3 object key (path)
            content_type: MIME type (optional)
            public: Jika True, file akan public-read dan return direct URL

        Returns:
            URL untuk file yang diupload (public URL jika public=True, presigned jika tidak)
        """
        # Validasi key
        key = self._validate_key(key)

        # Convert input ke bytes
        if isinstance(file_obj, bytes):
            data = file_obj
        elif isinstance(file_obj, str):
            data = file_obj.encode('utf-8')
        else:
            # File-like object
            if hasattr(file_obj, 'seek'):
                file_obj.seek(0)
            data = file_obj.read() if hasattr(file_obj, 'read') else bytes(file_obj)
            if isinstance(data, str):
                data = data.encode('utf-8')

        if not isinstance(data, bytes):
            raise ValueError(f"Expected bytes, got {type(data)}")

        # AWS4 Signature calculation
        method = 'PUT'
        service = 's3'
        content_type = content_type or 'application/octet-stream'

        # Timestamps
        t = datetime.utcnow()
        amz_date = t.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = t.strftime('%Y%m%d')

        # Canonical URI (path-style: /bucket/key)
        canonical_uri = '/' + self.bucket + '/' + quote(key, safe='/')

        # Canonical query string (empty for PUT)
        canonical_querystring = ''

        # Payload hash
        payload_hash = hashlib.sha256(data).hexdigest()

        # Canonical headers (must be in alphabetical order)
        if public:
            canonical_headers = (
                f'content-length:{len(data)}\n'
                f'content-type:{content_type}\n'
                f'host:{self.host}\n'
                f'x-amz-acl:public-read\n'
                f'x-amz-content-sha256:{payload_hash}\n'
                f'x-amz-date:{amz_date}\n'
            )
            signed_headers = 'content-length;content-type;host;x-amz-acl;x-amz-content-sha256;x-amz-date'
        else:
            canonical_headers = (
                f'content-length:{len(data)}\n'
                f'content-type:{content_type}\n'
                f'host:{self.host}\n'
                f'x-amz-content-sha256:{payload_hash}\n'
                f'x-amz-date:{amz_date}\n'
            )
            signed_headers = 'content-length;content-type;host;x-amz-content-sha256;x-amz-date'

        # Canonical request
        canonical_request = (
            f'{method}\n'
            f'{canonical_uri}\n'
            f'{canonical_querystring}\n'
            f'{canonical_headers}\n'
            f'{signed_headers}\n'
            f'{payload_hash}'
        )

        # String to sign
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = f'{date_stamp}/{self.region}/{service}/aws4_request'
        string_to_sign = (
            f'{algorithm}\n'
            f'{amz_date}\n'
            f'{credential_scope}\n'
            + hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        )

        # Signature
        signing_key = self._get_signature_key(date_stamp)
        signature = hmac.new(
            signing_key,
            string_to_sign.encode('utf-8'),
            hashlib.sha256,
        ).hexdigest()

        # Authorization header
        authorization_header = (
            f'{algorithm} '
            f'Credential={self.access_key}/{credential_scope}, '
            f'SignedHeaders={signed_headers}, '
            f'Signature={signature}'
        )

        # Request headers
        headers = {
            'Content-Type': content_type,
            'Content-Length': str(len(data)),
            'Host': self.host,
            'X-Amz-Date': amz_date,
            'X-Amz-Content-Sha256': payload_hash,
            'Authorization': authorization_header,
        }

        # Add ACL header for public uploads
        if public:
            headers['X-Amz-Acl'] = 'public-read'

        # Make request
        url = f'{self.endpoint_url}/{self.bucket}/{quote(key, safe="/")}'

        response = requests.put(url, data=data, headers=headers, timeout=60)

        if response.status_code not in [200, 201, 204]:
            raise Exception(
                f"S3 upload failed [{response.status_code}]: {response.text}"
            )

        # Return public URL or presigned URL
        if public:
            return self.get_public_url(key)
        return self.get_url(key)

    def download_file(self, key: str) -> bytes:
        """Download file dari S3."""
        key = self._validate_key(key)
        obj = self.s3.get_object(Bucket=self.bucket, Key=key)
        return obj['Body'].read()

    def stream_file(self, key: str):
        """Stream file dari S3."""
        key = self._validate_key(key)
        obj = self.s3.get_object(Bucket=self.bucket, Key=key)
        return obj['Body']

    def delete_file(self, key: str):
        """Hapus file dari S3."""
        key = self._validate_key(key)
        self.s3.delete_object(Bucket=self.bucket, Key=key)

    def get_url(self, key: str, expires: int = 3600) -> str:
        """Generate presigned URL untuk download."""
        key = self._validate_key(key)
        return self.s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': self.bucket, 'Key': key},
            ExpiresIn=expires
        )

    def get_public_url(self, key: str) -> str:
        """Generate public URL untuk file (tanpa signature, file harus public-read)."""
        key = self._validate_key(key)
        return f'{self.endpoint_url}/{self.bucket}/{quote(key, safe="/")}'

    def file_exists(self, key: str) -> bool:
        """Check apakah file ada di S3."""
        try:
            key = self._validate_key(key)
            self.s3.head_object(Bucket=self.bucket, Key=key)
            return True
        except (ClientError, ValueError):
            return False


# Lazy singleton – resolved on first access to avoid import-time failures
# when S3 environment variables are not configured.
_s3_service_instance: Optional[S3Service] = None


def get_s3_service() -> S3Service:
    """Return the shared S3Service singleton, creating it on first call."""
    global _s3_service_instance
    if _s3_service_instance is None:
        _s3_service_instance = S3Service()
    return _s3_service_instance
