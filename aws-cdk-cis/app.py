#!/usr/bin/env python3

from aws_cdk import core

from aws_cdk_cis.aws_cdk_cis_stack import AwsCdkCisStack


app = core.App()
AwsCdkCisStack(app, "aws-cdk-cis")

app.synth()
