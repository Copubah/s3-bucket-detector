"""
S3 Bucket Remediator
Automatically fixes public S3 bucket configurations
"""

import json
import logging
from typing import Dict, Any, List
import boto3
from botocore.exceptions import ClientError
import time

logger = logging.getLogger(__name__)

# Error codes that warrant a retry
_THROTTLE_CODES = frozenset(['Throttling', 'RequestLimitExceeded', 'TooManyRequests'])


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
            logger.info('Successfully remediated bucket %s: %s', bucket_name, result['actions_taken'])
        else:
            logger.warning('Remediation incomplete for bucket %s: %s', bucket_name, result['errors'])

        return result

    def _enable_public_access_block(self, bucket_name: str) -> Dict[str, Any]:
        """Enable all Public Access Block settings"""
        try:
            self._retry_with_backoff(
                self.s3_client.put_public_access_block,
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            logger.info('Enabled Public Access Block for bucket %s', bucket_name)
            return {'success': True}
        except ClientError as e:
            error_msg = 'Failed to enable Public Access Block: %s' % e
            logger.error(error_msg)
            return {'success': False, 'error': error_msg}

    def _remove_public_acl(self, bucket_name: str) -> Dict[str, Any]:
        """Remove public ACL by setting to private"""
        try:
            self._retry_with_backoff(
                self.s3_client.put_bucket_acl,
                Bucket=bucket_name,
                ACL='private'
            )
            logger.info('Set bucket ACL to private for %s', bucket_name)
            return {'success': True}
        except ClientError as e:
            error_msg = 'Failed to set ACL to private: %s' % e
            logger.error(error_msg)
            return {'success': False, 'error': error_msg}

    def _remediate_bucket_policy(self, bucket_name: str, detection_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remediate public bucket policy.

        Strategy:
        - Fetch the live policy and remove only the statements identified as
          public (matched by Sid, falling back to re-evaluating each statement
          against the stored public_statements list).
        - If the remaining statement list is empty, delete the policy entirely.
        - This preserves legitimate statements (CloudFront OAI, cross-account
          access, etc.) that were not flagged as public.
        """
        try:
            policy_details = detection_result.get('details', {}).get('policy', {})
            public_statements = policy_details.get('public_statements', [])

            if not public_statements:
                return {'success': True, 'action': 'no_public_policy_found'}

            # Build a set of Sids to remove for fast lookup
            public_sids = {s['sid'] for s in public_statements if s.get('sid') != 'N/A'}

            # Fetch the current live policy (may differ from the snapshot in
            # detection_result if the bucket was modified in the interim)
            try:
                live_policy_str = self.s3_client.get_bucket_policy(Bucket=bucket_name)['Policy']
                live_policy = json.loads(live_policy_str)
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    return {'success': True, 'action': 'no_policy_to_delete'}
                raise

            all_statements = live_policy.get('Statement', [])

            # Keep statements that are NOT in the public set.
            # A statement is considered public if its Sid matches, or (when no
            # Sid is available) if it appears in the snapshot's public list by
            # identity comparison.
            public_statement_snapshots = [
                (s.get('sid', 'N/A'), tuple(sorted(
                    s['actions'] if isinstance(s['actions'], list) else [s['actions']]
                )))
                for s in public_statements
            ]

            def _is_public_statement(stmt: Dict[str, Any]) -> bool:
                sid = stmt.get('Sid', 'N/A')
                if sid != 'N/A' and sid in public_sids:
                    return True
                # Fallback: match by action list when Sid is absent
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                action_key = tuple(sorted(actions))
                return (sid, action_key) in public_statement_snapshots

            remaining = [s for s in all_statements if not _is_public_statement(s)]

            if not remaining:
                # No legitimate statements left — delete the whole policy
                self._retry_with_backoff(
                    self.s3_client.delete_bucket_policy,
                    Bucket=bucket_name
                )
                logger.info('Deleted entire bucket policy for %s (no legitimate statements remained)', bucket_name)
                return {'success': True, 'action': 'deleted_bucket_policy'}

            # Re-apply policy with only the safe statements
            live_policy['Statement'] = remaining
            self._retry_with_backoff(
                self.s3_client.put_bucket_policy,
                Bucket=bucket_name,
                Policy=json.dumps(live_policy)
            )
            logger.info(
                'Removed %d public statement(s) from bucket policy for %s, %d statement(s) retained',
                len(all_statements) - len(remaining),
                bucket_name,
                len(remaining)
            )
            return {'success': True, 'action': 'removed_public_statements_from_policy'}

        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                return {'success': True, 'action': 'no_policy_to_delete'}

            error_msg = 'Failed to remediate bucket policy: %s' % e
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

            logger.error('Failed to verify remediation for %s: %s', bucket_name, e)
            return {'is_public': None, 'error': str(e)}

    def _retry_with_backoff(self, func, *args, **kwargs):
        """Execute function with exponential backoff retry on throttle errors"""
        for attempt in range(self.max_retries):
            try:
                return func(*args, **kwargs)
            except ClientError as e:
                error_code = e.response['Error']['Code']

                if error_code in _THROTTLE_CODES:
                    if attempt < self.max_retries - 1:
                        delay = self.retry_delay * (2 ** attempt)
                        logger.warning('Throttled on attempt %d, retrying in %ds...', attempt + 1, delay)
                        time.sleep(delay)
                        continue

                raise

        raise Exception('Max retries (%d) exceeded' % self.max_retries)
