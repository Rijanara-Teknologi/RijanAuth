"""
Tests for S3 backup upload/download in backup_service.py.

Verifies that:
- When a custom endpoint_url is set, path-style addressing is used automatically
- When no endpoint_url is set (AWS), 'auto' addressing is used (default)
- An explicit 'addressing_style' credential overrides the automatic choice
- An explicit 'signature_version' credential is passed to BotocoreConfig
- _upload_s3 and _download_s3 propagate the correct Config to boto3.client()
"""
import pytest
from unittest.mock import MagicMock, patch, call


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_s3_mock(put_response=None, get_body=b'backup-data'):
    """Return a MagicMock boto3 S3 client."""
    mock_client = MagicMock()
    mock_client.put_object.return_value = put_response or {}
    response_body = MagicMock()
    response_body.read.return_value = get_body
    mock_client.get_object.return_value = {'Body': response_body}
    return mock_client


def _base_creds(**overrides):
    creds = {
        'aws_access_key_id': 'AKIATEST',
        'aws_secret_access_key': 'secret',
        'bucket_name': 'my-backup-bucket',
        'region': 'us-east-1',
    }
    creds.update(overrides)
    return creds


# ---------------------------------------------------------------------------
# _upload_s3 – addressing style
# ---------------------------------------------------------------------------

class TestUploadS3AddressingStyle:

    def _run_upload(self, mock_client, creds):
        """Run _upload_s3 with the provided creds, patching boto3.client."""
        from apps.services.backup_service import _upload_s3

        with patch('boto3.client', return_value=mock_client) as mock_boto:
            object_key, uri = _upload_s3(b'zip-data', 'backup.zip', creds)
            return mock_boto, object_key, uri

    def test_path_style_used_when_endpoint_url_set(self):
        """
        When endpoint_url is provided and no addressing_style override is given,
        boto3.client must be called with Config(s3={'addressing_style': 'path'}).
        This is required for IDCloudHost, MinIO and similar providers.
        """
        from botocore.config import Config
        mock_client = _make_s3_mock()
        creds = _base_creds(endpoint_url='https://is3.cloudhost.id')

        mock_boto, object_key, uri = self._run_upload(mock_client, creds)

        _, kwargs = mock_boto.call_args
        config = kwargs.get('config')
        assert config is not None, "boto3.client() must receive a 'config' kwarg"
        assert isinstance(config, Config)
        assert config.s3.get('addressing_style') == 'path', (
            "Path-style addressing must be used when endpoint_url is set"
        )

    def test_auto_style_used_when_no_endpoint_url(self):
        """
        When endpoint_url is NOT provided (native AWS), boto3.client must be
        called with Config(s3={'addressing_style': 'auto'}).
        """
        from botocore.config import Config
        mock_client = _make_s3_mock()
        creds = _base_creds()  # no endpoint_url

        mock_boto, object_key, uri = self._run_upload(mock_client, creds)

        _, kwargs = mock_boto.call_args
        config = kwargs.get('config')
        assert config is not None
        assert isinstance(config, Config)
        assert config.s3.get('addressing_style') == 'auto', (
            "Auto addressing style must be used for AWS S3"
        )

    def test_explicit_addressing_style_overrides_default(self):
        """
        If the user explicitly sets 'addressing_style' in credentials, that
        value must be used, even when endpoint_url is also set.
        """
        from botocore.config import Config
        mock_client = _make_s3_mock()
        creds = _base_creds(
            endpoint_url='https://is3.cloudhost.id',
            addressing_style='virtual',
        )

        mock_boto, object_key, uri = self._run_upload(mock_client, creds)

        _, kwargs = mock_boto.call_args
        config = kwargs.get('config')
        assert config is not None
        assert config.s3.get('addressing_style') == 'virtual'

    def test_signature_version_forwarded_when_set(self):
        """
        When 'signature_version' is set in credentials, it must be passed
        to BotocoreConfig.
        """
        from botocore.config import Config
        mock_client = _make_s3_mock()
        creds = _base_creds(
            endpoint_url='https://is3.cloudhost.id',
            signature_version='s3',
        )

        mock_boto, object_key, uri = self._run_upload(mock_client, creds)

        _, kwargs = mock_boto.call_args
        config = kwargs.get('config')
        assert config is not None
        # botocore.config.Config stores signature_version directly
        assert config.signature_version == 's3'

    def test_endpoint_url_forwarded_to_boto3(self):
        """
        The endpoint_url from creds must be passed as a top-level kwarg to
        boto3.client(), not buried inside Config.
        """
        mock_client = _make_s3_mock()
        endpoint = 'https://is3.cloudhost.id'
        creds = _base_creds(endpoint_url=endpoint)

        mock_boto, _, _ = self._run_upload(mock_client, creds)

        _, kwargs = mock_boto.call_args
        assert kwargs.get('endpoint_url') == endpoint

    def test_object_key_and_uri_returned(self):
        """
        Verify the returned (object_key, s3_uri) tuple is formed correctly.
        """
        mock_client = _make_s3_mock()
        creds = _base_creds(
            endpoint_url='https://is3.cloudhost.id',
            prefix='backups',
        )

        _, object_key, uri = self._run_upload(mock_client, creds)

        assert object_key == 'backups/backup.zip'
        assert uri == 's3://my-backup-bucket/backups/backup.zip'


# ---------------------------------------------------------------------------
# _download_s3 – addressing style
# ---------------------------------------------------------------------------

class TestDownloadS3AddressingStyle:

    def _run_download(self, mock_client, creds):
        from apps.services.backup_service import _download_s3

        with patch('boto3.client', return_value=mock_client) as mock_boto:
            data = _download_s3('backups/backup.zip', creds)
            return mock_boto, data

    def test_path_style_used_when_endpoint_url_set(self):
        from botocore.config import Config
        mock_client = _make_s3_mock()
        creds = _base_creds(endpoint_url='https://is3.cloudhost.id')

        mock_boto, data = self._run_download(mock_client, creds)

        _, kwargs = mock_boto.call_args
        config = kwargs.get('config')
        assert config is not None
        assert isinstance(config, Config)
        assert config.s3.get('addressing_style') == 'path'

    def test_auto_style_used_when_no_endpoint_url(self):
        from botocore.config import Config
        mock_client = _make_s3_mock()
        creds = _base_creds()

        mock_boto, data = self._run_download(mock_client, creds)

        _, kwargs = mock_boto.call_args
        config = kwargs.get('config')
        assert config is not None
        assert config.s3.get('addressing_style') == 'auto'

    def test_explicit_addressing_style_overrides_default(self):
        mock_client = _make_s3_mock()
        creds = _base_creds(
            endpoint_url='https://is3.cloudhost.id',
            addressing_style='auto',
        )

        mock_boto, _ = self._run_download(mock_client, creds)

        _, kwargs = mock_boto.call_args
        config = kwargs.get('config')
        assert config is not None
        assert config.s3.get('addressing_style') == 'auto'

    def test_returns_body_bytes(self):
        expected = b'zip-content-here'
        mock_client = _make_s3_mock(get_body=expected)
        creds = _base_creds(endpoint_url='https://is3.cloudhost.id')

        _, data = self._run_download(mock_client, creds)

        assert data == expected
