import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta
from pendragondi_cloud_audit.providers import aws_s3

# A fixture to represent the current time, making tests deterministic
@pytest.fixture
def mock_now():
    return datetime(2024, 1, 31, 12, 0, 0, tzinfo=timezone.utc)

# A fixture for mock S3 object data
@pytest.fixture
def mock_s3_objects(mock_now):
    stale_time = mock_now - timedelta(days=100)
    recent_time = mock_now - timedelta(days=10)

    return [
        # Stale file
        {"Key": "stale-file.txt", "Size": 1024, "LastModified": stale_time},
        # Recent file
        {"Key": "recent-file.log", "Size": 2048, "LastModified": recent_time},
        # Duplicate file 1 (should be grouped with 3)
        {"Key": "docs/report.pdf", "Size": 4096, "LastModified": recent_time},
        # Duplicate file 2 (should be grouped with 1)
        {"Key": "backup/report.pdf", "Size": 4096, "LastModified": recent_time},
        # Unique large file
        {"Key": "archive.zip", "Size": 99999, "LastModified": stale_time},
    ]

# A fixture to patch the boto3 S3 client
@pytest.fixture
def mock_boto3_client(mock_s3_objects):
    # Mock the S3 client and its paginator
    mock_s3 = MagicMock()
    mock_paginator = MagicMock()
    mock_paginate_iterator = iter([
        {"Contents": mock_s3_objects}
    ])

    mock_paginator.paginate.return_value = mock_paginate_iterator
    mock_s3.get_paginator.return_value = mock_paginator

    # Patch boto3.client to return our mock S3 client
    with patch('boto3.client', return_value=mock_s3) as mock_client:
        yield mock_client

@patch('pendragondi_cloud_audit.providers.aws_s3.datetime')
def test_stale_file_detection(mock_datetime, mock_boto3_client, mock_now):
    """
    Tests if stale files are correctly identified based on the --days-stale parameter.
    """
    # Arrange: Mock datetime.now() to return our fixed time
    mock_datetime.now.return_value = mock_now
    mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)


    # Act
    results = aws_s3.scan(bucket="test-bucket", days_stale=90, limit=None)

    # Assert
    stale_files = {r["path"] for r in results if r["is_stale"]}

    # Assert that the file modified 100 days ago is marked as stale
    assert "s3://test-bucket/stale-file.txt" in stale_files
    assert "s3://test-bucket/archive.zip" in stale_files

    # Assert that the file modified 10 days ago is not marked as stale
    assert "s3://test-bucket/recent-file.log" not in stale_files

@patch('pendragondi_cloud_audit.providers.aws_s3.datetime')
def test_duplicate_id_assignment_is_correct(mock_datetime, mock_boto3_client, mock_now):
    """
    Tests that files with the same size and last_modified date receive the same duplicate_id.
    This test is expected to FAIL with the current buggy implementation.
    """
    # Arrange: Mock datetime.now() to ensure deterministic test
    mock_datetime.now.return_value = mock_now
    mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)

    # Act
    results = aws_s3.scan(bucket="test-bucket", days_stale=90, limit=None)

    # Find the duplicate files in the results
    dupe1 = next(r for r in results if r["path"] == "s3://test-bucket/docs/report.pdf")
    dupe2 = next(r for r in results if r["path"] == "s3://test-bucket/backup/report.pdf")
    unique_file = next(r for r in results if r["path"] == "s3://test-bucket/recent-file.log")

    # Assert
    # 1. The two duplicate files must have a duplicate_id
    assert dupe1["duplicate_id"] is not None
    assert dupe2["duplicate_id"] is not None

    # 2. The duplicate_id for the two duplicate files must be the SAME
    assert dupe1["duplicate_id"] == dupe2["duplicate_id"]

    # 3. The unique file should not have a duplicate_id
    assert unique_file["duplicate_id"] is None


@patch('pendragondi_cloud_audit.providers.aws_s3.datetime')
def test_oversized_file_detection(mock_datetime, mock_boto3_client, mock_now):
    """
    Tests that files are correctly flagged as oversized based on the --oversized-mb parameter.
    """
    # Arrange
    mock_datetime.now.return_value = mock_now
    mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)

    # Act: Scan with a 4MB oversized threshold.
    # The mock data has files of size 1024 (1KB), 2048 (2KB), 4096 (4KB), and 99999 (~97KB)
    results = aws_s3.scan(bucket="test-bucket", days_stale=90, oversized_mb=0.005) # 0.005 MB = 5120 bytes

    # Assert
    oversized_files = {r["path"] for r in results if r["is_oversized"]}
    small_files = {r["path"] for r in results if not r["is_oversized"]}

    assert "s3://test-bucket/archive.zip" in oversized_files # 99999 bytes > 5120 bytes

    assert "s3://test-bucket/stale-file.txt" in small_files # 1024 < 5120
    assert "s3://test-bucket/recent-file.log" in small_files # 2048 < 5120
    assert "s3://test-bucket/docs/report.pdf" in small_files # 4096 < 5120
