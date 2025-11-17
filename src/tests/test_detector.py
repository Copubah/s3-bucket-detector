"""
Unit tests for S3 Bucket Detector
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError
import json

from detector import S3BucketDetector


@pytest.fixture
def detector():
    """Create detector instance"""
    return S3BucketDetector()


@pytest.fixture
def mock_s3_client():
    """Mock S3 client"""
    with patch('detector.boto3.client') as mock:
        yield mock.return_value


class TestPublicAccessBlock:
    """Test Public Access Block detection"""
    
    def test_all_blocks_enabled(self, detector, mock_s3_client):
        """Test bucket with all PAB settings enabled"""
        mock_s3_client.get_public_access_block.return_value = {
            'PublicAccessBlockConfiguration': {
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        }
        
        result = detector._check_public_access_block('test-bucket')
        
        assert result['exists'] is True
        assert result['all_blocked'] is True
    
    def test_partial_blocks_enabled(self, detector, mock_s3_client):
        """Test bucket with partial PAB settings"""
        mock_s3_client.get_public_access_block.return_value = {
            'PublicAccessBlockConfiguration': {
                'BlockPublicAcls': True,
                'IgnorePublicAcls': False,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': False
            }
        }
        
        result = detector._check_public_access_block('test-bucket')
        
        assert result['exists'] is True
        assert result['all_blocked'] is False
    
    def test_no_pab_configuration(self, detector, mock_s3_client):
        """Test bucket without PAB configuration"""
        mock_s3_client.get_public_access_block.side_effect = ClientError(
            {'Error': {'Code': 'NoSuchPublicAccessBlockConfiguration'}},
            'GetPublicAccessBlock'
        )
        
        result = detector._check_public_access_block('test-bucket')
        
        assert result['exists'] is False
        assert result['all_blocked'] is False


class TestBucketACL:
    """Test bucket ACL detection"""
    
    def test_public_read_acl(self, detector, mock_s3_client):
        """Test bucket with public-read ACL"""
        mock_s3_client.get_bucket_acl.return_value = {
            'Grants': [
                {
                    'Grantee': {
                        'Type': 'Group',
                        'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'
                    },
                    'Permission': 'READ'
                }
            ]
        }
        
        result = detector._check_bucket_acl('test-bucket')
        
        assert result['is_public'] is True
        assert len(result['public_grants']) == 1
        assert result['public_grants'][0]['grantee'] == 'AllUsers'
        assert result['public_grants'][0]['permission'] == 'READ'
    
    def test_authenticated_users_acl(self, detector, mock_s3_client):
        """Test bucket with AuthenticatedUsers ACL"""
        mock_s3_client.get_bucket_acl.return_value = {
            'Grants': [
                {
                    'Grantee': {
                        'Type': 'Group',
                        'URI': 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                    },
                    'Permission': 'WRITE'
                }
            ]
        }
        
        result = detector._check_bucket_acl('test-bucket')
        
        assert result['is_public'] is True
        assert result['public_grants'][0]['grantee'] == 'AuthenticatedUsers'
    
    def test_private_acl(self, detector, mock_s3_client):
        """Test bucket with private ACL"""
        mock_s3_client.get_bucket_acl.return_value = {
            'Grants': [
                {
                    'Grantee': {
                        'Type': 'CanonicalUser',
                        'ID': 'abc123'
                    },
                    'Permission': 'FULL_CONTROL'
                }
            ]
        }
        
        result = detector._check_bucket_acl('test-bucket')
        
        assert result['is_public'] is False
        assert len(result['public_grants']) == 0


class TestBucketPolicy:
    """Test bucket policy detection"""
    
    def test_public_policy_wildcard_principal(self, detector, mock_s3_client):
        """Test bucket with public policy (wildcard principal)"""
        policy = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Sid': 'PublicRead',
                    'Effect': 'Allow',
                    'Principal': '*',
                    'Action': 's3:GetObject',
                    'Resource': 'arn:aws:s3:::test-bucket/*'
                }
            ]
        }
        
        mock_s3_client.get_bucket_policy.return_value = {
            'Policy': json.dumps(policy)
        }
        
        result = detector._check_bucket_policy('test-bucket')
        
        assert result['exists'] is True
        assert result['is_public'] is True
        assert len(result['public_statements']) == 1
    
    def test_public_policy_aws_wildcard(self, detector, mock_s3_client):
        """Test bucket with AWS wildcard principal"""
        policy = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Effect': 'Allow',
                    'Principal': {'AWS': '*'},
                    'Action': 's3:*',
                    'Resource': 'arn:aws:s3:::test-bucket/*'
                }
            ]
        }
        
        mock_s3_client.get_bucket_policy.return_value = {
            'Policy': json.dumps(policy)
        }
        
        result = detector._check_bucket_policy('test-bucket')
        
        assert result['is_public'] is True
    
    def test_policy_with_conditions(self, detector, mock_s3_client):
        """Test policy with restrictive conditions (not truly public)"""
        policy = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Effect': 'Allow',
                    'Principal': '*',
                    'Action': 's3:GetObject',
                    'Resource': 'arn:aws:s3:::test-bucket/*',
                    'Condition': {
                        'IpAddress': {
                            'aws:SourceIp': '192.0.2.0/24'
                        }
                    }
                }
            ]
        }
        
        mock_s3_client.get_bucket_policy.return_value = {
            'Policy': json.dumps(policy)
        }
        
        result = detector._check_bucket_policy('test-bucket')
        
        # With conditions, not considered truly public
        assert result['is_public'] is False
    
    def test_no_bucket_policy(self, detector, mock_s3_client):
        """Test bucket without policy"""
        mock_s3_client.get_bucket_policy.side_effect = ClientError(
            {'Error': {'Code': 'NoSuchBucketPolicy'}},
            'GetBucketPolicy'
        )
        
        result = detector._check_bucket_policy('test-bucket')
        
        assert result['exists'] is False
        assert result['is_public'] is False


class TestComprehensiveDetection:
    """Test comprehensive bucket detection"""
    
    @patch('detector.S3BucketDetector._check_public_access_block')
    @patch('detector.S3BucketDetector._check_bucket_acl')
    @patch('detector.S3BucketDetector._check_bucket_policy')
    @patch('detector.S3BucketDetector._check_bucket_policy_status')
    @patch('detector.S3BucketDetector._get_bucket_location')
    @patch('detector.S3BucketDetector._get_bucket_tags')
    @patch('detector.S3BucketDetector._is_allowlisted')
    def test_public_bucket_detection(
        self, mock_allowlist, mock_tags, mock_location, mock_policy_status,
        mock_policy, mock_acl, mock_pab, detector
    ):
        """Test detection of public bucket"""
        mock_pab.return_value = {'exists': False, 'all_blocked': False}
        mock_acl.return_value = {'is_public': True, 'public_grants': []}
        mock_policy.return_value = {'exists': False, 'is_public': False}
        mock_policy_status.return_value = {'is_public': True}
        mock_location.return_value = 'us-east-1'
        mock_tags.return_value = {}
        mock_allowlist.return_value = False
        
        result = detector.check_bucket_public_access('test-bucket')
        
        assert result['is_public'] is True
        assert 'public_acl' in result['exposure_types']
    
    @patch('detector.S3BucketDetector._check_public_access_block')
    @patch('detector.S3BucketDetector._check_bucket_acl')
    @patch('detector.S3BucketDetector._check_bucket_policy')
    @patch('detector.S3BucketDetector._check_bucket_policy_status')
    @patch('detector.S3BucketDetector._get_bucket_location')
    @patch('detector.S3BucketDetector._get_bucket_tags')
    @patch('detector.S3BucketDetector._is_allowlisted')
    def test_private_bucket_detection(
        self, mock_allowlist, mock_tags, mock_location, mock_policy_status,
        mock_policy, mock_acl, mock_pab, detector
    ):
        """Test detection of private bucket"""
        mock_pab.return_value = {'exists': True, 'all_blocked': True}
        mock_acl.return_value = {'is_public': False, 'public_grants': []}
        mock_policy.return_value = {'exists': False, 'is_public': False}
        mock_policy_status.return_value = {'is_public': False}
        mock_location.return_value = 'us-east-1'
        mock_tags.return_value = {}
        mock_allowlist.return_value = False
        
        result = detector.check_bucket_public_access('test-bucket')
        
        assert result['is_public'] is False
        assert len(result['exposure_types']) == 0
    
    @patch('detector.S3BucketDetector._check_public_access_block')
    @patch('detector.S3BucketDetector._check_bucket_acl')
    @patch('detector.S3BucketDetector._check_bucket_policy')
    @patch('detector.S3BucketDetector._check_bucket_policy_status')
    @patch('detector.S3BucketDetector._get_bucket_location')
    @patch('detector.S3BucketDetector._get_bucket_tags')
    @patch('detector.S3BucketDetector._is_allowlisted')
    def test_allowlisted_bucket(
        self, mock_allowlist, mock_tags, mock_location, mock_policy_status,
        mock_policy, mock_acl, mock_pab, detector
    ):
        """Test allowlisted bucket is not flagged"""
        mock_pab.return_value = {'exists': False, 'all_blocked': False}
        mock_acl.return_value = {'is_public': True, 'public_grants': []}
        mock_policy.return_value = {'exists': False, 'is_public': False}
        mock_policy_status.return_value = {'is_public': True}
        mock_location.return_value = 'us-east-1'
        mock_tags.return_value = {'PublicAccessApproved': 'true'}
        mock_allowlist.return_value = True
        
        result = detector.check_bucket_public_access('test-bucket')
        
        assert result['is_public'] is False
        assert result.get('allowlisted') is True


class TestAllowlist:
    """Test allowlist functionality"""
    
    def test_tag_based_allowlist(self, detector):
        """Test bucket allowlisted by tag"""
        tags = {'PublicAccessApproved': 'true'}
        
        result = detector._is_allowlisted('test-bucket', tags)
        
        assert result is True
    
    @patch.dict('os.environ', {'ALLOWED_PUBLIC_BUCKETS': 'bucket1,bucket2,bucket3'})
    def test_env_based_allowlist(self, detector):
        """Test bucket allowlisted by environment variable"""
        result = detector._is_allowlisted('bucket2', {})
        
        assert result is True
    
    def test_not_allowlisted(self, detector):
        """Test bucket not in allowlist"""
        result = detector._is_allowlisted('test-bucket', {})
        
        assert result is False
