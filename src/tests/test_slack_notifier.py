"""
Unit tests for Slack Notifier
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError
import json

from slack_notifier import SlackNotifier


@pytest.fixture
def notifier():
    """Create notifier instance"""
    return SlackNotifier('arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret')


@pytest.fixture
def mock_secrets_client():
    """Mock Secrets Manager client"""
    with patch('slack_notifier.boto3.client') as mock:
        yield mock.return_value


@pytest.fixture
def mock_http():
    """Mock HTTP client"""
    with patch('slack_notifier.urllib3.PoolManager') as mock:
        yield mock.return_value


@pytest.fixture
def sample_report():
    """Sample detection report"""
    return {
        'correlation_id': 'test-123',
        'timestamp': 1700000000,
        'bucket_name': 'test-bucket',
        'account_id': '123456789012',
        'region': 'us-east-1',
        'event_name': 'PutBucketAcl',
        'event_time': '2025-11-17T10:00:00Z',
        'user_identity': {
            'type': 'IAMUser',
            'userName': 'test-user'
        },
        'source_ip': '192.0.2.1',
        'detection_result': {
            'is_public': True,
            'exposure_types': ['public_acl'],
            'details': {}
        },
        'auto_remediate_enabled': False
    }


class TestWebhookRetrieval:
    """Test Slack webhook URL retrieval"""
    
    def test_get_webhook_url_success(self, notifier, mock_secrets_client):
        """Test successful webhook URL retrieval"""
        mock_secrets_client.get_secret_value.return_value = {
            'SecretString': json.dumps({'webhook_url': 'https://hooks.slack.com/test'})
        }
        
        url = notifier._get_webhook_url()
        
        assert url == 'https://hooks.slack.com/test'
        mock_secrets_client.get_secret_value.assert_called_once()
    
    def test_get_webhook_url_cached(self, notifier, mock_secrets_client):
        """Test webhook URL caching"""
        mock_secrets_client.get_secret_value.return_value = {
            'SecretString': json.dumps({'webhook_url': 'https://hooks.slack.com/test'})
        }
        
        url1 = notifier._get_webhook_url()
        url2 = notifier._get_webhook_url()
        
        assert url1 == url2
        # Should only call Secrets Manager once due to caching
        assert mock_secrets_client.get_secret_value.call_count == 1
    
    def test_get_webhook_url_failure(self, notifier, mock_secrets_client):
        """Test webhook URL retrieval failure"""
        mock_secrets_client.get_secret_value.side_effect = ClientError(
            {'Error': {'Code': 'ResourceNotFoundException'}},
            'GetSecretValue'
        )
        
        with pytest.raises(ClientError):
            notifier._get_webhook_url()


class TestMessageBuilding:
    """Test Slack message building"""
    
    def test_build_message_structure(self, notifier, sample_report):
        """Test message structure"""
        message = notifier._build_message(sample_report)
        
        assert 'blocks' in message
        assert 'text' in message
        assert len(message['blocks']) > 0
    
    def test_build_message_with_remediation(self, notifier, sample_report):
        """Test message with remediation info"""
        sample_report['remediation_result'] = {
            'success': True,
            'actions_taken': ['enabled_public_access_block', 'removed_public_acl']
        }
        
        message = notifier._build_message(sample_report)
        message_str = json.dumps(message)
        
        assert 'Auto-Remediated' in message_str
        assert 'enabled_public_access_block' in message_str
    
    def test_build_message_without_remediation(self, notifier, sample_report):
        """Test message without remediation"""
        message = notifier._build_message(sample_report)
        message_str = json.dumps(message)
        
        assert 'Manual Remediation Required' in message_str
    
    def test_build_message_includes_links(self, notifier, sample_report):
        """Test message includes console links"""
        message = notifier._build_message(sample_report)
        message_str = json.dumps(message)
        
        assert 's3.console.aws.amazon.com' in message_str
        assert 'cloudtrail' in message_str.lower()
    
    def test_build_message_includes_metadata(self, notifier, sample_report):
        """Test message includes all required metadata"""
        message = notifier._build_message(sample_report)
        message_str = json.dumps(message)
        
        assert sample_report['bucket_name'] in message_str
        assert sample_report['account_id'] in message_str
        assert sample_report['region'] in message_str
        assert sample_report['correlation_id'] in message_str


class TestSeverityCalculation:
    """Test severity calculation"""
    
    def test_critical_severity_multiple_exposures(self, notifier):
        """Test critical severity for multiple exposure types"""
        detection = {
            'exposure_types': ['public_acl', 'public_policy']
        }
        
        severity = notifier._calculate_severity(detection)
        
        assert severity == 'critical'
    
    def test_high_severity_public_acl(self, notifier):
        """Test high severity for public ACL"""
        detection = {
            'exposure_types': ['public_acl']
        }
        
        severity = notifier._calculate_severity(detection)
        
        assert severity == 'high'
    
    def test_high_severity_public_policy(self, notifier):
        """Test high severity for public policy"""
        detection = {
            'exposure_types': ['public_policy']
        }
        
        severity = notifier._calculate_severity(detection)
        
        assert severity == 'high'
    
    def test_medium_severity_pab_disabled(self, notifier):
        """Test medium severity for PAB disabled"""
        detection = {
            'exposure_types': ['public_access_block_disabled']
        }
        
        severity = notifier._calculate_severity(detection)
        
        assert severity == 'medium'
    
    def test_low_severity_default(self, notifier):
        """Test low severity as default"""
        detection = {
            'exposure_types': []
        }
        
        severity = notifier._calculate_severity(detection)
        
        assert severity == 'low'


class TestUserIdentityFormatting:
    """Test user identity formatting"""
    
    def test_format_iam_user(self, notifier):
        """Test IAM user formatting"""
        user_identity = {
            'type': 'IAMUser',
            'userName': 'john.doe'
        }
        
        result = notifier._format_user_identity(user_identity)
        
        assert result == 'john.doe'
    
    def test_format_assumed_role(self, notifier):
        """Test assumed role formatting"""
        user_identity = {
            'type': 'AssumedRole',
            'arn': 'arn:aws:sts::123456789012:assumed-role/MyRole/session-name'
        }
        
        result = notifier._format_user_identity(user_identity)
        
        assert result == 'session-name'
    
    def test_format_root_account(self, notifier):
        """Test root account formatting"""
        user_identity = {
            'type': 'Root'
        }
        
        result = notifier._format_user_identity(user_identity)
        
        assert result == 'Root Account'
    
    def test_format_unknown_identity(self, notifier):
        """Test unknown identity formatting"""
        user_identity = {
            'type': 'Unknown',
            'principalId': 'AIDAI123456789'
        }
        
        result = notifier._format_user_identity(user_identity)
        
        assert result == 'AIDAI123456789'


class TestSlackNotification:
    """Test Slack notification sending"""
    
    def test_send_alert_success(self, notifier, mock_secrets_client, mock_http, sample_report):
        """Test successful alert sending"""
        mock_secrets_client.get_secret_value.return_value = {
            'SecretString': json.dumps({'webhook_url': 'https://hooks.slack.com/test'})
        }
        
        mock_response = Mock()
        mock_response.status = 200
        mock_http.request.return_value = mock_response
        
        notifier.send_alert(sample_report)
        
        mock_http.request.assert_called_once()
        call_args = mock_http.request.call_args
        assert call_args[0][0] == 'POST'
        assert call_args[0][1] == 'https://hooks.slack.com/test'
    
    def test_send_alert_http_error(self, notifier, mock_secrets_client, mock_http, sample_report):
        """Test alert sending with HTTP error"""
        mock_secrets_client.get_secret_value.return_value = {
            'SecretString': json.dumps({'webhook_url': 'https://hooks.slack.com/test'})
        }
        
        mock_response = Mock()
        mock_response.status = 500
        mock_response.data = b'Internal Server Error'
        mock_http.request.return_value = mock_response
        
        with pytest.raises(Exception, match='Slack API returned status 500'):
            notifier.send_alert(sample_report)
    
    def test_send_alert_no_webhook(self, notifier, mock_secrets_client, sample_report):
        """Test alert sending without webhook URL"""
        mock_secrets_client.get_secret_value.return_value = {
            'SecretString': json.dumps({'webhook_url': ''})
        }
        
        with pytest.raises(Exception, match='Slack webhook URL not configured'):
            notifier.send_alert(sample_report)
