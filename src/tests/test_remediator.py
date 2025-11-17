"""
Unit tests for S3 Bucket Remediator
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError

from remediator import S3BucketRemediator


@pytest.fixture
def remediator():
    """Create remediator instance"""
    return S3BucketRemediator()


@pytest.fixture
def mock_s3_client():
    """Mock S3 client"""
    with patch('remediator.boto3.client') as mock:
        yield mock.return_value


class TestPublicAccessBlockRemediation:
    """Test Public Access Block remediation"""
    
    def test_enable_public_access_block_success(self, remediator, mock_s3_client):
        """Test successful PAB enablement"""
        mock_s3_client.put_public_access_block.return_value = {}
        
        result = remediator._enable_public_access_block('test-bucket')
        
        assert result['success'] is True
        mock_s3_client.put_public_access_block.assert_called_once()
        
        call_args = mock_s3_client.put_public_access_block.call_args
        config = call_args[1]['PublicAccessBlockConfiguration']
        assert config['BlockPublicAcls'] is True
        assert config['IgnorePublicAcls'] is True
        assert config['BlockPublicPolicy'] is True
        assert config['RestrictPublicBuckets'] is True
    
    def test_enable_public_access_block_failure(self, remediator, mock_s3_client):
        """Test PAB enablement failure"""
        mock_s3_client.put_public_access_block.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Access Denied'}},
            'PutPublicAccessBlock'
        )
        
        result = remediator._enable_public_access_block('test-bucket')
        
        assert result['success'] is False
        assert 'error' in result


class TestACLRemediation:
    """Test ACL remediation"""
    
    def test_remove_public_acl_success(self, remediator, mock_s3_client):
        """Test successful ACL remediation"""
        mock_s3_client.put_bucket_acl.return_value = {}
        
        result = remediator._remove_public_acl('test-bucket')
        
        assert result['success'] is True
        mock_s3_client.put_bucket_acl.assert_called_once_with(
            Bucket='test-bucket',
            ACL='private'
        )
    
    def test_remove_public_acl_failure(self, remediator, mock_s3_client):
        """Test ACL remediation failure"""
        mock_s3_client.put_bucket_acl.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Access Denied'}},
            'PutBucketAcl'
        )
        
        result = remediator._remove_public_acl('test-bucket')
        
        assert result['success'] is False


class TestPolicyRemediation:
    """Test bucket policy remediation"""
    
    def test_delete_public_policy_success(self, remediator, mock_s3_client):
        """Test successful policy deletion"""
        mock_s3_client.delete_bucket_policy.return_value = {}
        
        detection_result = {
            'details': {
                'policy': {
                    'public_statements': [
                        {'sid': 'PublicRead', 'actions': ['s3:GetObject']}
                    ]
                }
            }
        }
        
        result = remediator._remediate_bucket_policy('test-bucket', detection_result)
        
        assert result['success'] is True
        assert result['action'] == 'deleted_bucket_policy'
        mock_s3_client.delete_bucket_policy.assert_called_once_with(Bucket='test-bucket')
    
    def test_no_public_policy(self, remediator, mock_s3_client):
        """Test when no public policy exists"""
        detection_result = {
            'details': {
                'policy': {
                    'public_statements': []
                }
            }
        }
        
        result = remediator._remediate_bucket_policy('test-bucket', detection_result)
        
        assert result['success'] is True
        assert result['action'] == 'no_public_policy_found'
    
    def test_policy_already_deleted(self, remediator, mock_s3_client):
        """Test when policy is already deleted"""
        mock_s3_client.delete_bucket_policy.side_effect = ClientError(
            {'Error': {'Code': 'NoSuchBucketPolicy'}},
            'DeleteBucketPolicy'
        )
        
        detection_result = {
            'details': {
                'policy': {
                    'public_statements': [{'sid': 'test'}]
                }
            }
        }
        
        result = remediator._remediate_bucket_policy('test-bucket', detection_result)
        
        assert result['success'] is True
        assert result['action'] == 'no_policy_to_delete'


class TestComprehensiveRemediation:
    """Test comprehensive bucket remediation"""
    
    @patch('remediator.S3BucketRemediator._enable_public_access_block')
    @patch('remediator.S3BucketRemediator._remove_public_acl')
    @patch('remediator.S3BucketRemediator._remediate_bucket_policy')
    @patch('remediator.S3BucketRemediator._verify_remediation')
    @patch('remediator.time.sleep')
    def test_full_remediation_success(
        self, mock_sleep, mock_verify, mock_policy, mock_acl, mock_pab, remediator
    ):
        """Test successful full remediation"""
        mock_pab.return_value = {'success': True}
        mock_acl.return_value = {'success': True}
        mock_policy.return_value = {'success': True, 'action': 'deleted_bucket_policy'}
        mock_verify.return_value = {'is_public': False}
        
        detection_result = {
            'is_public': True,
            'exposure_types': ['public_access_block_disabled', 'public_acl', 'public_policy']
        }
        
        result = remediator.remediate_bucket('test-bucket', detection_result)
        
        assert result['success'] is True
        assert 'enabled_public_access_block' in result['actions_taken']
        assert 'removed_public_acl' in result['actions_taken']
        assert 'deleted_bucket_policy' in result['actions_taken']
    
    @patch('remediator.S3BucketRemediator._enable_public_access_block')
    @patch('remediator.S3BucketRemediator._verify_remediation')
    @patch('remediator.time.sleep')
    def test_partial_remediation_failure(
        self, mock_sleep, mock_verify, mock_pab, remediator
    ):
        """Test partial remediation failure"""
        mock_pab.return_value = {'success': False, 'error': 'Access Denied'}
        mock_verify.return_value = {'is_public': True}
        
        detection_result = {
            'is_public': True,
            'exposure_types': ['public_access_block_disabled']
        }
        
        result = remediator.remediate_bucket('test-bucket', detection_result)
        
        assert result['success'] is False
        assert len(result['errors']) > 0
    
    def test_no_remediation_needed(self, remediator):
        """Test when bucket is not public"""
        detection_result = {
            'is_public': False,
            'exposure_types': []
        }
        
        result = remediator.remediate_bucket('test-bucket', detection_result)
        
        assert result['success'] is True
        assert 'no remediation needed' in result['message'].lower()


class TestVerification:
    """Test remediation verification"""
    
    def test_verify_bucket_private(self, remediator, mock_s3_client):
        """Test verification of private bucket"""
        mock_s3_client.get_bucket_policy_status.return_value = {
            'PolicyStatus': {'IsPublic': False}
        }
        
        result = remediator._verify_remediation('test-bucket')
        
        assert result['is_public'] is False
    
    def test_verify_bucket_still_public(self, remediator, mock_s3_client):
        """Test verification when bucket is still public"""
        mock_s3_client.get_bucket_policy_status.return_value = {
            'PolicyStatus': {'IsPublic': True}
        }
        
        result = remediator._verify_remediation('test-bucket')
        
        assert result['is_public'] is True
    
    def test_verify_no_policy(self, remediator, mock_s3_client):
        """Test verification when no policy exists"""
        mock_s3_client.get_bucket_policy_status.side_effect = ClientError(
            {'Error': {'Code': 'NoSuchBucketPolicy'}},
            'GetBucketPolicyStatus'
        )
        
        result = remediator._verify_remediation('test-bucket')
        
        assert result['is_public'] is False


class TestRetryLogic:
    """Test retry with exponential backoff"""
    
    @patch('remediator.time.sleep')
    def test_retry_on_throttling(self, mock_sleep, remediator, mock_s3_client):
        """Test retry on throttling error"""
        mock_func = Mock()
        mock_func.side_effect = [
            ClientError({'Error': {'Code': 'Throttling'}}, 'TestOperation'),
            ClientError({'Error': {'Code': 'Throttling'}}, 'TestOperation'),
            {'success': True}
        ]
        
        result = remediator._retry_with_backoff(mock_func)
        
        assert result == {'success': True}
        assert mock_func.call_count == 3
        assert mock_sleep.call_count == 2
    
    @patch('remediator.time.sleep')
    def test_max_retries_exceeded(self, mock_sleep, remediator):
        """Test max retries exceeded"""
        mock_func = Mock()
        mock_func.side_effect = ClientError(
            {'Error': {'Code': 'Throttling'}},
            'TestOperation'
        )
        
        with pytest.raises(Exception, match='Max retries'):
            remediator._retry_with_backoff(mock_func)
        
        assert mock_func.call_count == 3
