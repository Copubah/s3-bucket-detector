"""
S3 Bucket Public Access Detector
Checks various S3 configurations to determine if a bucket is publicly accessible
"""

import logging
from typing import Dict, Any, List
import boto3
from botocore.exceptions import ClientError
import json

logger = logging.getLogger(__name__)

class S3BucketDetector:
    """Detects public access configurations in S3 buckets"""
    
    def __init__(self):
        self.s3_client = boto3.client('s3')
        
    def check_bucket_public_access(self, bucket_name: str) -> Dict[str, Any]:
        """
        Comprehensive check for public bucket access
        
        Args:
            bucket_name: Name of the S3 bucket
            
        Returns:
            Dictionary with detection results
        """
        result = {
            'is_public': False,
            'bucket_name': bucket_name,
            'exposure_types': [],
            'details': {}
        }
        
        try:
            # Check 1: Public Access Block settings
            pab_result = self._check_public_access_block(bucket_name)
            result['details']['public_access_block'] = pab_result
            
            if not pab_result.get('all_blocked', False):
                result['exposure_types'].append('public_access_block_disabled')
            
            # Check 2: Bucket ACL
            acl_result = self._check_bucket_acl(bucket_name)
            result['details']['acl'] = acl_result
            
            if acl_result.get('is_public', False):
                result['exposure_types'].append('public_acl')
                result['is_public'] = True
            
            # Check 3: Bucket Policy
            policy_result = self._check_bucket_policy(bucket_name)
            result['details']['policy'] = policy_result
            
            if policy_result.get('is_public', False):
                result['exposure_types'].append('public_policy')
                result['is_public'] = True
            
            # Check 4: Bucket Policy Status (AWS-provided check)
            policy_status = self._check_bucket_policy_status(bucket_name)
            result['details']['policy_status'] = policy_status
            
            if policy_status.get('is_public', False):
                result['is_public'] = True
            
            # Check 5: Bucket location and tags
            result['details']['location'] = self._get_bucket_location(bucket_name)
            result['details']['tags'] = self._get_bucket_tags(bucket_name)
            
            # Check if bucket is in allowlist
            if self._is_allowlisted(bucket_name, result['details']['tags']):
                result['is_public'] = False
                result['allowlisted'] = True
                logger.info(f"Bucket {bucket_name} is allowlisted")
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchBucket':
                logger.warning(f"Bucket {bucket_name} does not exist")
                result['error'] = 'NoSuchBucket'
            elif error_code == 'AccessDenied':
                logger.error(f"Access denied to bucket {bucket_name}")
                result['error'] = 'AccessDenied'
            else:
                logger.error(f"Error checking bucket {bucket_name}: {str(e)}")
                result['error'] = str(e)
        
        return result
    
    def _check_public_access_block(self, bucket_name: str) -> Dict[str, Any]:
        """Check Public Access Block configuration"""
        try:
            response = self.s3_client.get_public_access_block(Bucket=bucket_name)
            config = response['PublicAccessBlockConfiguration']
            
            all_blocked = (
                config.get('BlockPublicAcls', False) and
                config.get('IgnorePublicAcls', False) and
                config.get('BlockPublicPolicy', False) and
                config.get('RestrictPublicBuckets', False)
            )
            
            return {
                'exists': True,
                'configuration': config,
                'all_blocked': all_blocked
            }
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                return {
                    'exists': False,
                    'all_blocked': False
                }
            raise
    
    def _check_bucket_acl(self, bucket_name: str) -> Dict[str, Any]:
        """Check bucket ACL for public grants"""
        try:
            response = self.s3_client.get_bucket_acl(Bucket=bucket_name)
            grants = response.get('Grants', [])
            
            public_grants = []
            for grant in grants:
                grantee = grant.get('Grantee', {})
                grantee_type = grantee.get('Type', '')
                grantee_uri = grantee.get('URI', '')
                
                # Check for AllUsers or AuthenticatedUsers
                if grantee_type == 'Group' and grantee_uri in [
                    'http://acs.amazonaws.com/groups/global/AllUsers',
                    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                ]:
                    public_grants.append({
                        'grantee': grantee_uri.split('/')[-1],
                        'permission': grant.get('Permission', '')
                    })
            
            return {
                'is_public': len(public_grants) > 0,
                'public_grants': public_grants,
                'total_grants': len(grants)
            }
        except ClientError as e:
            logger.error(f"Error checking ACL for {bucket_name}: {str(e)}")
            return {'is_public': False, 'error': str(e)}
    
    def _check_bucket_policy(self, bucket_name: str) -> Dict[str, Any]:
        """Check bucket policy for public access"""
        try:
            response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_str = response['Policy']
            policy = json.loads(policy_str)
            
            public_statements = []
            
            for statement in policy.get('Statement', []):
                effect = statement.get('Effect', '')
                principal = statement.get('Principal', {})
                
                # Check for wildcard principal
                is_public_principal = False
                if principal == '*':
                    is_public_principal = True
                elif isinstance(principal, dict):
                    if principal.get('AWS') == '*':
                        is_public_principal = True
                
                if effect == 'Allow' and is_public_principal:
                    # Check if there are restrictive conditions
                    conditions = statement.get('Condition', {})
                    if not conditions:  # No conditions = truly public
                        public_statements.append({
                            'sid': statement.get('Sid', 'N/A'),
                            'actions': statement.get('Action', []),
                            'resources': statement.get('Resource', [])
                        })
            
            return {
                'exists': True,
                'is_public': len(public_statements) > 0,
                'public_statements': public_statements,
                'policy': policy
            }
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                return {'exists': False, 'is_public': False}
            logger.error(f"Error checking policy for {bucket_name}: {str(e)}")
            return {'is_public': False, 'error': str(e)}
    
    def _check_bucket_policy_status(self, bucket_name: str) -> Dict[str, Any]:
        """Use AWS's built-in public policy check"""
        try:
            response = self.s3_client.get_bucket_policy_status(Bucket=bucket_name)
            policy_status = response.get('PolicyStatus', {})
            
            return {
                'is_public': policy_status.get('IsPublic', False)
            }
        except ClientError as e:
            if e.response['Error']['Code'] in ['NoSuchBucketPolicy', 'NoSuchBucket']:
                return {'is_public': False}
            logger.error(f"Error checking policy status for {bucket_name}: {str(e)}")
            return {'is_public': False, 'error': str(e)}
    
    def _get_bucket_location(self, bucket_name: str) -> str:
        """Get bucket region"""
        try:
            response = self.s3_client.get_bucket_location(Bucket=bucket_name)
            location = response.get('LocationConstraint')
            return location if location else 'us-east-1'
        except ClientError:
            return 'unknown'
    
    def _get_bucket_tags(self, bucket_name: str) -> Dict[str, str]:
        """Get bucket tags"""
        try:
            response = self.s3_client.get_bucket_tagging(Bucket=bucket_name)
            tags = {}
            for tag in response.get('TagSet', []):
                tags[tag['Key']] = tag['Value']
            return tags
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchTagSet':
                return {}
            return {}
    
    def _is_allowlisted(self, bucket_name: str, tags: Dict[str, str]) -> bool:
        """
        Check if bucket is in allowlist
        
        Buckets can be allowlisted by:
        1. Tag: PublicAccessApproved=true
        2. Environment variable ALLOWED_PUBLIC_BUCKETS
        """
        # Check tag
        if tags.get('PublicAccessApproved', '').lower() == 'true':
            return True
        
        # Check environment variable
        import os
        allowed_buckets = os.environ.get('ALLOWED_PUBLIC_BUCKETS', '').split(',')
        allowed_buckets = [b.strip() for b in allowed_buckets if b.strip()]
        
        return bucket_name in allowed_buckets
