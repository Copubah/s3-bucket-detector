"""
S3 Bucket Remediator
Automatically fixes public S3 bucket configurations
"""

import logging
from typing import Dict, Any, List
import boto3
from botocore.exceptions import ClientError
import time

logger = logging.getLogger(__name__)

class S3BucketRemediator:
    """Remediates public S3 bucket configurations"""
    
    def __init__(self):
        self.s3_client = boto3.client('s3')
        self.max_retries = 3
        self.retry_delay = 1  # seconds
        
    def remediate_bucket(self, bucket_name: str, detection_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remediate public bucket access
        
        Args:
            bucket_name: Name of the S3 bucket
            detection_result: Detection result from detector
            
        Returns:
            Dictionary with remediation results
        """
        result = {
            'success': False,
            'bucket_name': bucket_name,
            'actions_taken': [],
            'errors': []
        }
        
        if not detection_result.get('is_public', False):
            result['success'] = True
            result['message'] = 'Bucket is not public, no remediation needed'
            return result
        
        exposure_types = detection_result.get('exposure_types', [])
        
        # Action 1: Enable Public Access Block (most effective)
        if 'public_access_block_disabled' in exposure_types:
            pab_result = self._enable_public_access_block(bucket_name)
            if pab_result['success']:
                result['actions_taken'].append('enabled_public_access_block')
            else:
                result['errors'].append(pab_result.get('error', 'Unknown error'))
        
        # Action 2: Remove public ACL
        if 'public_acl' in exposure_types:
            acl_result = self._remove_public_acl(bucket_name)
            if acl_result['success']:
                result['actions_taken'].append('removed_public_acl')
            else:
                result['errors'].append(acl_result.get('error', 'Unknown error'))
        
        # Action 3: Remove or modify public bucket policy
        if 'public_policy' in exposure_types:
            policy_result = self._remediate_bucket_policy(bucket_name, detection_result)
            if policy_result['success']:
                result['actions_taken'].append(policy_result['action'])
            else:
                result['errors'].append(policy_result.get('error', 'Unknown error'))
        
        # Verify remediation
        time.sleep(2)  # Wait for AWS to propagate changes
        verification = self._verify_remediation(bucket_name)
        result['verification'] = verification
        result['success'] = not verification.get('is_public', True)
        
        if result['success']:
            logger.info(f"Successfully remediated bucket {bucket_name}: {result['actions_taken']}")
        else:
            logger.warning(f"Remediation incomplete for bucket {bucket_name}: {result['errors']}")
        
        return result
    
    def _enable_public_access_block(self, bucket_name: str) -> Dict[str, Any]:
        """Enable all Public Access Block settings"""
        try:
            self.s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            logger.info(f"Enabled Public Access Block for bucket {bucket_name}")
            return {'success': True}
        except ClientError as e:
            error_msg = f"Failed to enable Public Access Block: {str(e)}"
            logger.error(error_msg)
            return {'success': False, 'error': error_msg}
    
    def _remove_public_acl(self, bucket_name: str) -> Dict[str, Any]:
        """Remove public ACL by setting to private"""
        try:
            self.s3_client.put_bucket_acl(
                Bucket=bucket_name,
                ACL='private'
            )
            logger.info(f"Set bucket ACL to private for {bucket_name}")
            return {'success': True}
        except ClientError as e:
            error_msg = f"Failed to set ACL to private: {str(e)}"
            logger.error(error_msg)
            return {'success': False, 'error': error_msg}
    
    def _remediate_bucket_policy(self, bucket_name: str, detection_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remediate public bucket policy
        
        Strategy:
        1. If policy only has public statements, delete the entire policy
        2. If policy has mixed statements, remove only public statements (complex, risky)
        3. For safety, we delete the entire policy and log for manual review
        """
        try:
            policy_details = detection_result.get('details', {}).get('policy', {})
            public_statements = policy_details.get('public_statements', [])
            
            if not public_statements:
                return {'success': True, 'action': 'no_public_policy_found'}
            
            # For safety, delete the entire policy
            # In production, you might want to be more surgical
            self.s3_client.delete_bucket_policy(Bucket=bucket_name)
            
            logger.warning(
                f"Deleted bucket policy for {bucket_name}. "
                f"Manual review recommended. Public statements: {public_statements}"
            )
            
            return {
                'success': True,
                'action': 'deleted_bucket_policy',
                'note': 'Manual review recommended'
            }
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                return {'success': True, 'action': 'no_policy_to_delete'}
            
            error_msg = f"Failed to remediate bucket policy: {str(e)}"
            logger.error(error_msg)
            return {'success': False, 'error': error_msg}
    
    def _verify_remediation(self, bucket_name: str) -> Dict[str, Any]:
        """Verify that bucket is no longer public"""
        try:
            # Quick check using policy status
            response = self.s3_client.get_bucket_policy_status(Bucket=bucket_name)
            is_public = response.get('PolicyStatus', {}).get('IsPublic', False)
            
            return {'is_public': is_public}
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                # No policy = likely not public (if PAB is enabled)
                return {'is_public': False}
            
            logger.error(f"Failed to verify remediation for {bucket_name}: {str(e)}")
            return {'is_public': None, 'error': str(e)}
    
    def _retry_with_backoff(self, func, *args, **kwargs):
        """Execute function with exponential backoff retry"""
        for attempt in range(self.max_retries):
            try:
                return func(*args, **kwargs)
            except ClientError as e:
                error_code = e.response['Error']['Code']
                
                if error_code in ['Throttling', 'RequestLimitExceeded', 'TooManyRequests']:
                    if attempt < self.max_retries - 1:
                        delay = self.retry_delay * (2 ** attempt)
                        logger.warning(f"Throttled, retrying in {delay}s...")
                        time.sleep(delay)
                        continue
                
                raise
        
        raise Exception(f"Max retries ({self.max_retries}) exceeded")
