from aws_cdk import (
    core,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_cloudtrail as cloudtrail,
    aws_cloudwatch as cloudwatch,
    aws_logs as logs,
    aws_s3 as s3,
    aws_config as config,
    aws_kms as kms,
    aws_sns as sns,
    aws_cloudwatch_actions as cloudwatch_actions,
    aws_securityhub as securityhub,
    cloudformation_include as cfn_inc,
)


class AwsCdkCisStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # enable_ebs_default_encryption = ec2.EbsDeviceOptionsBase.
        # enable_guardduty = guardduty.CfnDetector.enable("true")
        # password_policy = iam.

        # securityhub_instance = securityhub.CfnHub(self, 'SecurityHub')

        cloudtrail_bucket_accesslogs = s3.Bucket(self, "CloudTrailS3Accesslogs",
                                                 block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                                 encryption=s3.BucketEncryption.S3_MANAGED,
                                                 removal_policy=core.RemovalPolicy.RETAIN
                                                 )

        cloudtrail_bucket = s3.Bucket(self, "CloudTrailS3",
                                      block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                      encryption=s3.BucketEncryption.S3_MANAGED,
                                      removal_policy=core.RemovalPolicy.RETAIN,
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
                                  removal_policy=core.RemovalPolicy.RETAIN,
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

        # 2.9 – Ensure VPC flow logging is enabled in all VPCs
        # vpc = ec2.Vpc.from_lookup(self, "VPC",
        #                           is_default=True,
        #                           )

        # S3 for VPC flow logs
        # vpc_flow_logs_bucket = s3.Bucket(self, "VPCFlowLogsBucket",
        #                                  block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        #                                  encryption=s3.BucketEncryption.S3_MANAGED,
        #                                  removal_policy=core.RemovalPolicy.RETAIN
        #                                  )

        security_notifications_topic = sns.Topic(self, 'CIS_Topic',
                                                 display_name='CIS_Topic',
                                                 topic_name='CIS_Topic'
                                                 )
        sns.Subscription(self, 'CIS_Subscription',
                         topic=security_notifications_topic,
                         protocol=sns.SubscriptionProtocol.EMAIL,
                         endpoint='example@example.com'
                         )

        cloudwatch_actions_cis = cloudwatch_actions.SnsAction(
            security_notifications_topic)

        # 3.1 – Ensure a log metric filter and alarm exist for unauthorized API calls
        cis_metricfilter_alarms = {
            'CIS-3.1-UnauthorizedAPICalls': '($.errorCode="*UnauthorizedOperation") || ($.errorCode="AccessDenied*")',
            'CIS-3.2-ConsoleSigninWithoutMFA': '($.eventName="ConsoleLogin") && ($.additionalEventData.MFAUsed !="Yes")',
            'RootAccountUsageAlarm': '$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"',
            'CIS-3.4-IAMPolicyChanges': '($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy)',
            'CIS-3.5-CloudTrailChanges': '($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)',
            'CIS-3.6-ConsoleAuthenticationFailure': '($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")',
            'CIS-3.7-DisableOrDeleteCMK': '($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))',
            'CIS-3.8-S3BucketPolicyChanges': '($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))',
            'CIS-3.9-AWSConfigChanges': '($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))',
            'CIS-3.10-SecurityGroupChanges': '($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)',
            'CIS-3.11-NetworkACLChanges': '($.eventName=CreateNetworkAcl) || ($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || ($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || ($.eventName=ReplaceNetworkAclAssociation)',
            'CIS-3.12-NetworkGatewayChanges': '($.eventName=CreateCustomerGateway) || ($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || ($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || ($.eventName=DetachInternetGateway)',
            'CIS-3.13-RouteTableChanges': '($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable)',
            'CIS-3.14-VPCChanges': '($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || ($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || ($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)',
        }
        for x, y in cis_metricfilter_alarms.items():
            str_x = str(x)
            str_y = str(y)
            logs.MetricFilter(self, "MetricFilter_"+str_x,
                              log_group=trail.log_group,
                              filter_pattern=logs.JsonPattern(
                                  json_pattern_string=str_y),
                              metric_name=str_x,
                              metric_namespace="LogMetrics",
                              metric_value='1'
                              )
            cloudwatch.Alarm(self, "Alarm_"+str_x,
                             alarm_name=str_x,
                             alarm_description=str_x,
                             statistic='Sum',
                             period=core.Duration.minutes(5),
                             comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
                             evaluation_periods=1,
                             threshold=1,
                             metric=cloudwatch.Metric(metric_name=str_x,
                                                      namespace="LogMetrics"
                                                      ),

                             ).add_alarm_action(cloudwatch_actions_cis)

        # IAM Password Policy custom resource CIS 1.5 - 1.11
        cfn_template = cfn_inc.CfnInclude(self, "includeTemplate",
                                          template_file="account-password-policy.yaml",
                                          parameters={
                                                "MaxPasswordAge": 90,
                                                "MinimumPasswordLength": 14,
                                                "PasswordReusePrevention": 24,
                                                "RequireLowercaseCharacters": True,
                                                "RequireNumbers": True,
                                                "RequireSymbols": True,
                                                "RequireUppercaseCharacters": True,
                                          }
                                          )

        # CIS 1.20
        support_role = iam.Role(self, "SupportRole",
                                assumed_by=iam.AccountPrincipal(
                                    account_id=core.Stack.of(self).account),
                                managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                                    'AWSSupportAccess')],
                                role_name='AWSSupportAccess'
                                )

        # * EBS default encryption should be enabled
        # GuardDuty should be enabled

        # Destructive
        # * Delete default VPC
        # * The VPC default security group should not allow inbound and outbound traffic
        # delete from all SG 0.0.0.0/0 port 22,
