"""
Unit tests for lambda_function — focusing on idempotency and event parsing.
"""

import json
import pytest
from unittest.mock import MagicMock, patch, call
from botocore.exceptions import ClientError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_sqs_event(body: dict, message_id: str = 'msg-1') -> dict:
    return {
        'Records': [
            {
                'messageId': message_id,
                'body': json.dumps(body)
            }
        ]
    }


def _lambda_context():
    ctx = MagicMock()
    ctx.request_id = 'test-request-id'
    return ctx


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_module_globals():
    """Patch module-level AWS clients so tests don't hit real AWS."""
    with patch('lambda_function.s3_client'), \
         patch('lambda_function.cloudwatch_client'), \
         patch('lambda_function.detector'), \
         patch('lambda_function.remediator'), \
         patch('lambda_function.slack_notifier'):
        yield


# ---------------------------------------------------------------------------
# Tests: idempotency
# ---------------------------------------------------------------------------

class TestIdempotency:

    def test_duplicate_event_is_skipped(self):
        """A redelivered SQS record with the same eventID is not processed twice."""
        import lambda_function as lf

        event_id = 'evt-abc-123'
        body = {'detail': {'eventID': event_id, 'eventName': 'PutBucketAcl'}}

        # First call: put_item succeeds → process
        # Second call: ConditionalCheckFailedException → skip
        mock_ddb = MagicMock()
        mock_ddb.put_item.side_effect = [
            {},  # first delivery — claim succeeds
            ClientError(
                {'Error': {'Code': 'ConditionalCheckFailedException', 'Message': ''}},
                'PutItem'
            )  # second delivery — duplicate
        ]

        with patch.object(lf, 'dynamodb_client', mock_ddb), \
             patch.object(lf, 'IDEMPOTENCY_TABLE', 'idempotency-table'), \
             patch.object(lf, 'process_cloudtrail_event', return_value={'detected': False, 'remediated': False}) as mock_proc, \
             patch.object(lf, 'publish_metrics'):

            ctx = _lambda_context()
            sqs_event = _make_sqs_event(body)

            # First delivery
            lf.lambda_handler(sqs_event, ctx)
            assert mock_proc.call_count == 1

            # Second delivery (redelivery)
            lf.lambda_handler(sqs_event, ctx)
            # process_cloudtrail_event should NOT be called again
            assert mock_proc.call_count == 1

    def test_first_delivery_is_processed(self):
        """When no duplicate exists the event is processed normally."""
        import lambda_function as lf

        body = {'detail': {'eventID': 'evt-new', 'eventName': 'PutBucketPolicy'}}

        mock_ddb = MagicMock()
        mock_ddb.put_item.return_value = {}  # No conflict

        with patch.object(lf, 'dynamodb_client', mock_ddb), \
             patch.object(lf, 'IDEMPOTENCY_TABLE', 'idempotency-table'), \
             patch.object(lf, 'process_cloudtrail_event', return_value={'detected': False, 'remediated': False}) as mock_proc, \
             patch.object(lf, 'publish_metrics'):

            ctx = _lambda_context()
            lf.lambda_handler(_make_sqs_event(body), ctx)

        assert mock_proc.call_count == 1

    def test_idempotency_skipped_when_no_table_configured(self):
        """If IDEMPOTENCY_TABLE is not set, every delivery is processed."""
        import lambda_function as lf

        body = {'detail': {'eventID': 'evt-no-table', 'eventName': 'PutBucketAcl'}}

        with patch.object(lf, 'dynamodb_client', None), \
             patch.object(lf, 'IDEMPOTENCY_TABLE', None), \
             patch.object(lf, 'process_cloudtrail_event', return_value={'detected': False, 'remediated': False}) as mock_proc, \
             patch.object(lf, 'publish_metrics'):

            ctx = _lambda_context()
            lf.lambda_handler(_make_sqs_event(body), ctx)
            lf.lambda_handler(_make_sqs_event(body), ctx)

        assert mock_proc.call_count == 2

    def test_ddb_error_does_not_drop_event(self):
        """An unexpected DynamoDB error still allows the event to be processed."""
        import lambda_function as lf

        body = {'detail': {'eventID': 'evt-ddb-err', 'eventName': 'PutBucketAcl'}}

        mock_ddb = MagicMock()
        mock_ddb.put_item.side_effect = ClientError(
            {'Error': {'Code': 'ProvisionedThroughputExceededException', 'Message': ''}},
            'PutItem'
        )

        with patch.object(lf, 'dynamodb_client', mock_ddb), \
             patch.object(lf, 'IDEMPOTENCY_TABLE', 'idempotency-table'), \
             patch.object(lf, 'process_cloudtrail_event', return_value={'detected': False, 'remediated': False}) as mock_proc, \
             patch.object(lf, 'publish_metrics'):

            ctx = _lambda_context()
            lf.lambda_handler(_make_sqs_event(body), ctx)

        assert mock_proc.call_count == 1


# ---------------------------------------------------------------------------
# Tests: event normalisation (fix #1)
# ---------------------------------------------------------------------------

class TestEventNormalisation:

    def test_eventbridge_wrapped_event_is_passed_through(self):
        """EventBridge-wrapped events (with 'detail' key) are passed as-is."""
        import lambda_function as lf

        body = {
            'source': 'aws.s3',
            'detail': {
                'eventID': 'evt-eb',
                'eventName': 'PutBucketAcl',
                'requestParameters': {'bucketName': 'my-bucket'}
            }
        }

        with patch.object(lf, 'dynamodb_client', None), \
             patch.object(lf, 'IDEMPOTENCY_TABLE', None), \
             patch.object(lf, 'process_cloudtrail_event', return_value={'detected': False, 'remediated': False}) as mock_proc, \
             patch.object(lf, 'publish_metrics'):

            ctx = _lambda_context()
            lf.lambda_handler(_make_sqs_event(body), ctx)

        passed_event = mock_proc.call_args[0][0]
        # The full body (including 'detail') is passed so process_cloudtrail_event
        # can read body['detail']['eventName'] etc.
        assert passed_event['detail']['eventName'] == 'PutBucketAcl'

    def test_raw_cloudtrail_event_is_passed_through(self):
        """Raw CloudTrail records (without EventBridge wrapper) are also handled."""
        import lambda_function as lf

        body = {
            'detail': {
                'eventID': 'evt-raw',
                'eventName': 'PutBucketPolicy',
                'requestParameters': {'bucketName': 'raw-bucket'}
            }
        }

        with patch.object(lf, 'dynamodb_client', None), \
             patch.object(lf, 'IDEMPOTENCY_TABLE', None), \
             patch.object(lf, 'process_cloudtrail_event', return_value={'detected': False, 'remediated': False}) as mock_proc, \
             patch.object(lf, 'publish_metrics'):

            ctx = _lambda_context()
            lf.lambda_handler(_make_sqs_event(body), ctx)

        passed_event = mock_proc.call_args[0][0]
        assert passed_event['detail']['eventName'] == 'PutBucketPolicy'
