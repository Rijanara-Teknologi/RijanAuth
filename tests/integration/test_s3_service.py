"""
Tests for apps/services/s3_service.py

Verifies that:
- S3Service is importable and can be instantiated with constructor args
- _validate_key rejects invalid inputs and sanitises valid ones
- _sign produces correct HMAC-SHA256 digests
- _get_signature_key builds a correct AWS4 signing key
- upload_file builds the correct Authorization / AWS4 signature headers and
  calls requests.put with the right URL and headers
- upload_file raises on non-2xx HTTP responses
- upload_file returns a public URL when public=True
- upload_file returns a presigned URL when public=False
- download_file delegates to boto3 get_object and returns Body bytes
- stream_file returns the Body stream object
- delete_file calls boto3 delete_object
- file_exists returns True/False based on head_object / ClientError
- get_url calls generate_presigned_url with correct params
- get_public_url builds the expected URL string
- get_s3_service() returns a singleton S3Service instance
"""
import hashlib
import hmac
import pytest
from unittest.mock import MagicMock, patch, call
from botocore.exceptions import ClientError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_service(**kwargs):
    """Create an S3Service with test credentials (no env-var side-effects)."""
    from apps.services.s3_service import S3Service
    defaults = dict(
        endpoint_url='https://is3.cloudhost.id',
        access_key='AKIATEST',
        secret_key='secret123',
        region='us-east-1',
        bucket='test-bucket',
    )
    defaults.update(kwargs)
    with patch('boto3.client', return_value=MagicMock()):
        svc = S3Service(**defaults)
    return svc


# ---------------------------------------------------------------------------
# Instantiation
# ---------------------------------------------------------------------------

class TestS3ServiceInit:

    def test_instantiate_with_args(self):
        """S3Service must accept all parameters via constructor."""
        from apps.services.s3_service import S3Service
        with patch('boto3.client', return_value=MagicMock()):
            svc = S3Service(
                endpoint_url='https://example.com',
                access_key='AK',
                secret_key='SK',
                region='ap-southeast-1',
                bucket='my-bucket',
            )
        assert svc.endpoint_url == 'https://example.com'
        assert svc.access_key == 'AK'
        assert svc.secret_key == 'SK'
        assert svc.region == 'ap-southeast-1'
        assert svc.bucket == 'my-bucket'

    def test_endpoint_url_trailing_slash_stripped(self):
        """Trailing slashes on endpoint_url must be stripped."""
        from apps.services.s3_service import S3Service
        with patch('boto3.client', return_value=MagicMock()):
            svc = S3Service(endpoint_url='https://example.com/', access_key='A',
                            secret_key='S', region='r', bucket='b')
        assert svc.endpoint_url == 'https://example.com'

    def test_host_parsed_from_endpoint_url(self):
        """self.host must be the netloc portion of the endpoint URL."""
        from apps.services.s3_service import S3Service
        with patch('boto3.client', return_value=MagicMock()):
            svc = S3Service(endpoint_url='https://is3.cloudhost.id',
                            access_key='A', secret_key='S',
                            region='r', bucket='b')
        assert svc.host == 'is3.cloudhost.id'

    def test_boto3_client_created_with_path_style(self):
        """boto3.client must be created with path-style addressing."""
        from apps.services.s3_service import S3Service
        from botocore.config import Config as BotoConfig

        with patch('boto3.client') as mock_boto:
            mock_boto.return_value = MagicMock()
            S3Service(endpoint_url='https://is3.cloudhost.id',
                      access_key='AK', secret_key='SK',
                      region='us-east-1', bucket='b')

        _, kwargs = mock_boto.call_args
        config = kwargs.get('config')
        assert isinstance(config, BotoConfig)
        assert config.s3.get('addressing_style') == 'path'
        assert config.signature_version == 's3v4'

    def test_env_vars_used_as_defaults(self, monkeypatch):
        """When no constructor args are given, env vars must be used."""
        from apps.services.s3_service import S3Service

        monkeypatch.setenv('S3_ENDPOINT_URL', 'https://env-endpoint.example.com')
        monkeypatch.setenv('S3_ACCESS_KEY_ID', 'ENV_AK')
        monkeypatch.setenv('S3_SECRET_ACCESS_KEY', 'ENV_SK')
        monkeypatch.setenv('S3_REGION', 'eu-west-1')
        monkeypatch.setenv('S3_BUCKET_NAME', 'env-bucket')

        with patch('boto3.client', return_value=MagicMock()):
            svc = S3Service()

        assert svc.access_key == 'ENV_AK'
        assert svc.secret_key == 'ENV_SK'
        assert svc.region == 'eu-west-1'
        assert svc.bucket == 'env-bucket'


# ---------------------------------------------------------------------------
# _validate_key
# ---------------------------------------------------------------------------

class TestValidateKey:

    def _validate(self, key):
        svc = _make_service()
        return svc._validate_key(key)

    def test_valid_simple_key(self):
        assert self._validate('myfile.zip') == 'myfile.zip'

    def test_valid_path_key(self):
        assert self._validate('backups/2024/file.zip') == 'backups/2024/file.zip'

    def test_leading_trailing_slashes_stripped(self):
        assert self._validate('/backups/file.zip/') == 'backups/file.zip'

    def test_whitespace_stripped(self):
        assert self._validate('  backups/file.zip  ') == 'backups/file.zip'

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="kosong"):
            self._validate('')

    def test_slash_only_raises(self):
        """A key that becomes empty after stripping slashes must raise."""
        with pytest.raises(ValueError, match="kosong"):
            self._validate('///')

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="kosong"):
            self._validate('   ')

    def test_path_traversal_double_dot_raises(self):
        with pytest.raises(ValueError, match="path traversal"):
            self._validate('backups/../secret.zip')

    def test_backslash_raises(self):
        with pytest.raises(ValueError, match="karakter tidak valid"):
            self._validate('backups\\file.zip')

    def test_null_byte_raises(self):
        with pytest.raises(ValueError, match="karakter tidak valid"):
            self._validate('back\x00ups/file.zip')

    def test_newline_raises(self):
        with pytest.raises(ValueError, match="karakter tidak valid"):
            self._validate('backups\nfile.zip')

    def test_carriage_return_raises(self):
        with pytest.raises(ValueError, match="karakter tidak valid"):
            self._validate('backups\rfile.zip')

    def test_non_string_raises(self):
        with pytest.raises((ValueError, AttributeError)):
            self._validate(None)


# ---------------------------------------------------------------------------
# _sign
# ---------------------------------------------------------------------------

class TestSign:

    def test_sign_produces_correct_digest(self):
        """_sign must produce the same digest as a direct hmac.new call."""
        svc = _make_service()
        key = b'secret-key'
        msg = 'test-message'
        expected = hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
        assert svc._sign(key, msg) == expected

    def test_sign_returns_bytes(self):
        svc = _make_service()
        result = svc._sign(b'key', 'msg')
        assert isinstance(result, bytes)


# ---------------------------------------------------------------------------
# _get_signature_key
# ---------------------------------------------------------------------------

class TestGetSignatureKey:

    def test_returns_bytes(self):
        svc = _make_service()
        key = svc._get_signature_key('20240101')
        assert isinstance(key, bytes)
        assert len(key) == 32  # SHA-256 digest is 32 bytes

    def test_different_dates_produce_different_keys(self):
        svc = _make_service()
        k1 = svc._get_signature_key('20240101')
        k2 = svc._get_signature_key('20240102')
        assert k1 != k2


# ---------------------------------------------------------------------------
# upload_file
# ---------------------------------------------------------------------------

class TestUploadFile:

    def _run_upload(self, svc, file_data, key, **kwargs):
        """Run upload_file with requests.put mocked to return 200."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_presign = MagicMock(return_value='https://presigned.url/file')
        svc.s3.generate_presigned_url = mock_presign

        with patch('requests.put', return_value=mock_resp) as mock_put:
            result = svc.upload_file(file_data, key, **kwargs)
        return mock_put, result

    def test_upload_bytes_calls_put(self):
        """upload_file with bytes data must call requests.put."""
        svc = _make_service()
        mock_put, _ = self._run_upload(svc, b'zip-data', 'backups/file.zip')
        mock_put.assert_called_once()

    def test_upload_string_encoded_to_utf8(self):
        """String data must be UTF-8 encoded before upload."""
        svc = _make_service()
        mock_put, _ = self._run_upload(svc, 'text data', 'test.txt',
                                        content_type='text/plain')
        _, put_kwargs = mock_put.call_args
        assert put_kwargs['data'] == b'text data'

    def test_upload_url_contains_bucket_and_key(self):
        """PUT request URL must include bucket name and object key."""
        svc = _make_service()
        mock_put, _ = self._run_upload(svc, b'data', 'backups/file.zip')
        call_args = mock_put.call_args
        url = call_args[0][0] if call_args[0] else call_args[1].get('url', '')
        assert 'test-bucket' in url
        assert 'backups/file.zip' in url

    def test_authorization_header_present(self):
        """requests.put must receive an Authorization header."""
        svc = _make_service()
        mock_put, _ = self._run_upload(svc, b'data', 'key.zip')
        _, put_kwargs = mock_put.call_args
        headers = put_kwargs.get('headers', {})
        assert 'Authorization' in headers
        assert 'AWS4-HMAC-SHA256' in headers['Authorization']

    def test_amz_date_header_present(self):
        """X-Amz-Date header must be present in the PUT request."""
        svc = _make_service()
        mock_put, _ = self._run_upload(svc, b'data', 'key.zip')
        _, put_kwargs = mock_put.call_args
        headers = put_kwargs.get('headers', {})
        assert 'X-Amz-Date' in headers

    def test_content_length_header_correct(self):
        """Content-Length header must match the length of the data."""
        data = b'hello world'
        svc = _make_service()
        mock_put, _ = self._run_upload(svc, data, 'key.zip')
        _, put_kwargs = mock_put.call_args
        headers = put_kwargs.get('headers', {})
        assert headers.get('Content-Length') == str(len(data))

    def test_public_upload_adds_acl_header(self):
        """When public=True, X-Amz-Acl: public-read must be sent."""
        svc = _make_service()
        svc.s3.generate_presigned_url = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch('requests.put', return_value=mock_resp) as mock_put:
            svc.upload_file(b'data', 'pub/file.zip', public=True)
        _, put_kwargs = mock_put.call_args
        headers = put_kwargs.get('headers', {})
        assert headers.get('X-Amz-Acl') == 'public-read'

    def test_private_upload_no_acl_header(self):
        """When public=False (default), X-Amz-Acl must NOT be present."""
        svc = _make_service()
        svc.s3.generate_presigned_url = MagicMock(return_value='https://url')
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch('requests.put', return_value=mock_resp) as mock_put:
            svc.upload_file(b'data', 'priv/file.zip', public=False)
        _, put_kwargs = mock_put.call_args
        headers = put_kwargs.get('headers', {})
        assert 'X-Amz-Acl' not in headers

    def test_non_2xx_response_raises(self):
        """A non-2xx HTTP response must raise an Exception."""
        svc = _make_service()
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = 'Access Denied'
        with patch('requests.put', return_value=mock_resp):
            with pytest.raises(Exception, match='403'):
                svc.upload_file(b'data', 'key.zip')

    def test_public_upload_returns_public_url(self):
        """When public=True, return value must be the public URL."""
        svc = _make_service()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch('requests.put', return_value=mock_resp):
            url = svc.upload_file(b'data', 'pub/file.zip', public=True)
        assert 'test-bucket' in url
        assert 'pub/file.zip' in url

    def test_private_upload_returns_presigned_url(self):
        """When public=False, return value must be the presigned URL."""
        presigned = 'https://is3.cloudhost.id/test-bucket/key.zip?X-Amz-...'
        svc = _make_service()
        svc.s3.generate_presigned_url = MagicMock(return_value=presigned)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch('requests.put', return_value=mock_resp):
            url = svc.upload_file(b'data', 'key.zip')
        assert url == presigned

    def test_upload_key_validated(self):
        """upload_file must reject an invalid key (path traversal)."""
        svc = _make_service()
        with pytest.raises(ValueError, match='path traversal'):
            svc.upload_file(b'data', '../secret.zip')


# ---------------------------------------------------------------------------
# download_file
# ---------------------------------------------------------------------------

class TestDownloadFile:

    def test_returns_body_bytes(self):
        svc = _make_service()
        body_mock = MagicMock()
        body_mock.read.return_value = b'zip-content'
        svc.s3.get_object = MagicMock(return_value={'Body': body_mock})

        result = svc.download_file('backups/file.zip')

        svc.s3.get_object.assert_called_once_with(
            Bucket='test-bucket', Key='backups/file.zip'
        )
        assert result == b'zip-content'

    def test_invalid_key_raises(self):
        svc = _make_service()
        with pytest.raises(ValueError, match='path traversal'):
            svc.download_file('../secret.zip')


# ---------------------------------------------------------------------------
# stream_file
# ---------------------------------------------------------------------------

class TestStreamFile:

    def test_returns_body_stream(self):
        svc = _make_service()
        stream_mock = MagicMock()
        svc.s3.get_object = MagicMock(return_value={'Body': stream_mock})

        result = svc.stream_file('backups/file.zip')

        assert result is stream_mock

    def test_invalid_key_raises(self):
        svc = _make_service()
        with pytest.raises(ValueError, match='path traversal'):
            svc.stream_file('../etc/passwd')


# ---------------------------------------------------------------------------
# delete_file
# ---------------------------------------------------------------------------

class TestDeleteFile:

    def test_calls_delete_object(self):
        svc = _make_service()
        svc.s3.delete_object = MagicMock()

        svc.delete_file('backups/old.zip')

        svc.s3.delete_object.assert_called_once_with(
            Bucket='test-bucket', Key='backups/old.zip'
        )

    def test_invalid_key_raises(self):
        svc = _make_service()
        with pytest.raises(ValueError, match='path traversal'):
            svc.delete_file('../secret.zip')


# ---------------------------------------------------------------------------
# get_url (presigned)
# ---------------------------------------------------------------------------

class TestGetUrl:

    def test_calls_generate_presigned_url(self):
        svc = _make_service()
        presigned = 'https://presigned.example.com/file'
        svc.s3.generate_presigned_url = MagicMock(return_value=presigned)

        url = svc.get_url('backups/file.zip', expires=7200)

        svc.s3.generate_presigned_url.assert_called_once_with(
            'get_object',
            Params={'Bucket': 'test-bucket', 'Key': 'backups/file.zip'},
            ExpiresIn=7200,
        )
        assert url == presigned

    def test_default_expiry_is_3600(self):
        svc = _make_service()
        svc.s3.generate_presigned_url = MagicMock(return_value='https://url')

        svc.get_url('key.zip')

        _, kwargs = svc.s3.generate_presigned_url.call_args
        assert kwargs.get('ExpiresIn') == 3600

    def test_invalid_key_raises(self):
        svc = _make_service()
        with pytest.raises(ValueError, match='path traversal'):
            svc.get_url('../secret.zip')


# ---------------------------------------------------------------------------
# get_public_url
# ---------------------------------------------------------------------------

class TestGetPublicUrl:

    def test_url_format(self):
        svc = _make_service(endpoint_url='https://is3.cloudhost.id', bucket='my-bucket')
        url = svc.get_public_url('backups/file.zip')
        assert url == 'https://is3.cloudhost.id/my-bucket/backups/file.zip'

    def test_special_chars_in_key_encoded(self):
        svc = _make_service(endpoint_url='https://s3.amazonaws.com', bucket='bkt')
        url = svc.get_public_url('path/file with spaces.zip')
        assert ' ' not in url

    def test_invalid_key_raises(self):
        svc = _make_service()
        with pytest.raises(ValueError, match='path traversal'):
            svc.get_public_url('../secret.zip')


# ---------------------------------------------------------------------------
# file_exists
# ---------------------------------------------------------------------------

class TestFileExists:

    def test_returns_true_when_object_exists(self):
        svc = _make_service()
        svc.s3.head_object = MagicMock(return_value={})
        assert svc.file_exists('backups/file.zip') is True

    def test_returns_false_on_client_error(self):
        svc = _make_service()
        error_response = {'Error': {'Code': '404', 'Message': 'Not Found'}}
        svc.s3.head_object = MagicMock(
            side_effect=ClientError(error_response, 'HeadObject')
        )
        assert svc.file_exists('backups/missing.zip') is False

    def test_returns_false_on_invalid_key(self):
        """An invalid key must return False rather than raising."""
        svc = _make_service()
        assert svc.file_exists('../secret.zip') is False


# ---------------------------------------------------------------------------
# get_s3_service singleton
# ---------------------------------------------------------------------------

class TestGetS3ServiceSingleton:

    def test_returns_s3_service_instance(self, monkeypatch):
        """get_s3_service() must return an S3Service instance."""
        import apps.services.s3_service as s3_mod
        from apps.services.s3_service import S3Service

        # Reset singleton so the test is isolated
        s3_mod._s3_service_instance = None

        with patch('boto3.client', return_value=MagicMock()):
            svc = s3_mod.get_s3_service()

        assert isinstance(svc, S3Service)

    def test_returns_same_instance_on_repeated_calls(self, monkeypatch):
        """get_s3_service() must return the same object every time."""
        import apps.services.s3_service as s3_mod

        s3_mod._s3_service_instance = None

        with patch('boto3.client', return_value=MagicMock()):
            svc1 = s3_mod.get_s3_service()
            svc2 = s3_mod.get_s3_service()

        assert svc1 is svc2
