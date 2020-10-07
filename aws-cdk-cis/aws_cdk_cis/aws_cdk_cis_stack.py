from aws_cdk import (
    core,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_cloudtrail as cloudtrail,
    aws_logs as logs,
    aws_s3 as s3,
    aws_config as config,
    aws_kms as kms
)


class AwsCdkCisStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # enable_ebs_default_encryption = ec2.EbsDeviceOptionsBase.
        # enable_guardduty = guardduty.CfnDetector.enable("true")
        # password_policy = iam.

        cloudtrail_bucket_accesslogs = s3.Bucket(self, "CloudTrailS3Accesslogs",
                                                 block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                                 encryption=s3.BucketEncryption.S3_MANAGED,
                                                 removal_policy=core.RemovalPolicy.DESTROY
                                                 )

        cloudtrail_bucket = s3.Bucket(self, "CloudTrailS3",
                                      block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                      encryption=s3.BucketEncryption.S3_MANAGED,
                                      removal_policy=core.RemovalPolicy.DESTROY,
                                      server_access_logs_bucket=cloudtrail_bucket_accesslogs,
                                      )

        cloudtrail_kms = kms.Key(self, "CloudTrailKey",
                                 enable_key_rotation=True
                                 )

        trail = cloudtrail.Trail(self, "CloudTrail",
                                 enable_file_validation=True,
                                 is_multi_region_trail=True,
                                 include_global_service_events=True,
                                 send_to_cloud_watch_logs=True,
                                 cloud_watch_logs_retention=logs.RetentionDays.FOUR_MONTHS,
                                 bucket=cloudtrail_bucket,
                                 kms_key=cloudtrail_kms
                                 )
