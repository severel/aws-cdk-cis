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

        cloudtrail_kms.grant(iam.ServicePrincipal(
            'cloudtrail.amazonaws.com'), 'kms:DescribeKey')

        cloudtrail_kms.grant(iam.ServicePrincipal(
            'cloudtrail.amazonaws.com', conditions={
                'StringLike': {'kms:EncryptionContext:aws:cloudtrail:arn': 'arn:aws:cloudtrail:*:'+core.Stack.of(self).account+':trail/*'}
            }), 'kms:GenerateDataKey*')

        cloudtrail_kms.add_to_resource_policy(iam.PolicyStatement(
            actions=["kms:Decrypt", "kms:ReEncryptFrom"],
            conditions={
                'StringEquals': {'kms:CallerAccount': core.Stack.of(self).account},
                'StringLike': {'kms:EncryptionContext:aws:cloudtrail:arn': 'arn:aws:cloudtrail:*:'+core.Stack.of(self).account+':trail/*'}
            },
            effect=iam.Effect.ALLOW,
            principals=[iam.AnyPrincipal()],
            resources=['*']
        ))

        cloudtrail_kms.add_to_resource_policy(iam.PolicyStatement(
            actions=["kms:CreateAlias"],
            conditions={
                'StringEquals': {'kms:CallerAccount': core.Stack.of(self).account,
                                 'kms:ViaService': 'ec2.' +
                                 core.Stack.of(self).region+'.amazonaws.com'}
            },
            effect=iam.Effect.ALLOW,
            principals=[iam.AnyPrincipal()],
            resources=['*']
        ))

        cloudtrail_kms.add_to_resource_policy(iam.PolicyStatement(
            actions=["kms:Decrypt", "kms:ReEncryptFrom"],
            conditions={
                'StringEquals': {'kms:CallerAccount': core.Stack.of(self).account},
                'StringLike': {'kms:EncryptionContext:aws:cloudtrail:arn': 'arn:aws:cloudtrail:*:'+core.Stack.of(self).account+':trail/*'}
            },
            effect=iam.Effect.ALLOW,
            principals=[iam.AnyPrincipal()],
            resources=['*']
        ))

        # config_role = iam.Role(self, "ConfigRole",
        #                        assumed_by=iam.ServicePrincipal(
        #                            'config.amazonaws.com'),
        #                        managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
        #                            'service-role/AWS_ConfigRole')]
        #                        )

        config_role = iam.CfnServiceLinkedRole(self,
                                               id='ServiceLinkedRoleConfig',
                                               aws_service_name='config.amazonaws.com'
                                               )

        global_config = config.CfnConfigurationRecorder(self, 'ConfigRecorder',
                                                        name='default',
                                                        # role_arn=config_role.role_arn,
                                                        role_arn="arn:aws:iam::" + \
                                                        core.Stack.of(
                                                            self).account+":role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
                                                        # role_arn=config_role.get_att(
                                                        #     attribute_name='resource.arn').to_string(),
                                                        recording_group=config.CfnConfigurationRecorder.RecordingGroupProperty(
                                                            all_supported=True,
                                                            include_global_resource_types=True
                                                        )
                                                        )
        config_bucket = s3.Bucket(self, "ConfigS3",
                                  block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                  encryption=s3.BucketEncryption.S3_MANAGED,
                                  removal_policy=core.RemovalPolicy.DESTROY,
                                  )

        config_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                actions=['s3:GetBucketAcl'],
                effect=iam.Effect.ALLOW,
                # principals=[config_role],
                principals=[iam.ServicePrincipal('config.amazonaws.com')],
                resources=[config_bucket.bucket_arn]
            )
        )

        config_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                actions=['s3:PutObject'],
                effect=iam.Effect.ALLOW,
                # principals=[config_role],
                principals=[iam.ServicePrincipal('config.amazonaws.com')],
                resources=[config_bucket.arn_for_objects(
                    'AWSLogs/'+core.Stack.of(self).account+'/Config/*')],
                conditions={"StringEquals": {
                    's3:x-amz-acl': 'bucket-owner-full-control', }}
            )
        )

        config_delivery_stream = config.CfnDeliveryChannel(self, "ConfigDeliveryChannel",
                                                           s3_bucket_name=config_bucket.bucket_name
                                                           )
