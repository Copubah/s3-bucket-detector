"""
S3 Bucket Public Access Detector
Checks various S3 configurations to determine if a bucket is publicly accessible
"""

import json
import logging
import os
from typing import Dict, Any, List
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Condition keys that are considered restrictive (i.e. they genuinely limit
# who can access the resource).  Keys outside this set (e.g. aws:SourceIp
# with 0.0.0.0/0, tags, time-of-day, etc.) are NOT considered restrictive by
# this heuristic.
#
# Known limitation: evaluating whether a condition is truly restrictive
# requires understanding the specific values (e.g. 0.0.0.0/0 is not
# restrictive).  This implementation uses a key-name allowlist as a pragmatic
# approximation; a fully general evaluation would require re-implementing AWS
# IAM condition semantics.
_RESTRICTIVE_CONDITION_KEYS = frozenset([
    'aws:principalorgid',
    'aws:principalaccount',
    'aws:principalarn',
    'aws:sourcevpc',
    'aws:sourcevpce',
    'aws:sourceaccount',
    'aws:principaltype',
])

# CIDR ranges that are effectively unrestricted
_OPEN_CIDR_BLOCKS = frozenset(['0.0.0.0/0', '::/0'])


def _is_restrictive_condition(condition: Dict[str, Any]) -> bool:
    """
    Return True only when the Condition block actually restricts access to a
    non-public set of principals or networks.

    Strategy:
    1. If every condition operator/key pair uses a key from
       _RESTRICTIVE_CONDITION_KEYS, treat it as restrictive.
    2. If any IpAddress / NotIpAddress condition covers the whole internet
       (0.0.0.0/0 or ::/0), treat the whole block as non-restrictive.
    3. Otherwise fall back to treating unknown condition keys as
       non-restrictive (safe default).

    Known limitation: this heuristic does not evaluate condition *values*
    for most key types (e.g. it cannot tell whether a specific OrgID is a
    single account or a large org).  Complex condition logic (Bool, StringLike
    with wildcards, etc.) is not fully evaluated.
    """
    if not condition:
        return False

    for operator, key_value_map in condition.items():
        op_lower = operator.lower()
        for key, values in key_value_map.items():
            key_lower = key.lower()

            # Broad IP ranges are not restrictive
            if 'ipaddress' in op_lower:
                value_list = values if isinstance(values, list) else [values]
                if any(v in _OPEN_CIDR_BLOCKS for v in value_list):
                    return False

            # If ANY key is not in our restrictive allowlist, treat as
            # non-restrictive (conservative / safe default).
            if key_lower not in _RESTRICTIVE_CONDITION_KEYS:
                return False

    return True


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
                logger.info('Bucket %s is allowlisted', bucket_name)

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchBucket':
                logger.warning('Bucket %s does not exist', bucket_name)
                result['error'] = 'NoSuchBucket'
            elif error_code == 'AccessDenied':
                logger.error('Access denied to bucket %s', bucket_name)
                result['error'] = 'AccessDenied'
            else:
                logger.error('Error checking bucket %s: %s', bucket_name, e)
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
            logger.error('Error checking ACL for %s: %s', bucket_name, e)
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
                is_public_principal = (
                    principal == '*' or
                    (isinstance(principal, dict) and principal.get('AWS') == '*')
                )

                if effect == 'Allow' and is_public_principal:
                    condition = statement.get('Condition', {})
                    # Flag as public if there is no condition at all, or if the
                    # condition is not actually restrictive (e.g. a broad IP
                    # range, or an unrelated condition key).
                    if not _is_restrictive_condition(condition):
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
            logger.error('Error checking policy for %s: %s', bucket_name, e)
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
            logger.error('Error checking policy status for %s: %s', bucket_name, e)
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
        except ClientError:
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
        allowed_buckets = os.environ.get('ALLOWED_PUBLIC_BUCKETS', '').split(',')
        allowed_buckets = [b.strip() for b in allowed_buckets if b.strip()]

        return bucket_name in allowed_buckets
