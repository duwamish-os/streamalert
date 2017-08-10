from stream_alert.rule_processor.rules_engine import StreamRules
from helpers.base import in_set

rule = StreamRules.rule
disable = StreamRules.disable()

@disable
@rule(logs=['cloudtrail:api_events'],
      matchers=[],
      outputs=['aws-s3:main'])
def cloudtrail_critical_api(rec):
    """
    author:           airbnb_csirt
    description:      Alert on AWS API calls that stop or delete security/infrastructure logs.
                      Additionally, alert on AWS API calls that delete critical resources (VPCs, Subnets, DB's, ...)
    reference:        https://medium.com/@robwitoff/proactive-cloud-security-w-aws-organizations-d58695bcae16#.tx2e6iju0
    playbook:         (a) identify the AWS account in the log
                      (b) identify what resource(s) are impacted by the API call
                      (c) determine if the intent is valid, malicious or accidental
    """
    events_whitelist = {
        # VPC Flow Logs (~netflow)
        'DeleteFlowLogs',
        # Critical, large resources
        'DeleteSubnet',
        'DeleteVpc',
        'DeleteDBCluster',
        'DeleteCluster',
        # CloudTrail
        'DeleteTrail',
        'UpdateTrail',
        'StopLogging',
        # AWS Config
        'DeleteDeliveryChannel',
        'StopConfigurationRecorder',
        # CloudWatch
        'DeleteRule',
        'DisableRule'
    }

    return in_set(rec['eventName'], events_whitelist)

@rule(logs=['cloudwatch:events'],
      outputs=['aws-s3:main'],
      req_subkeys={'detail': ['eventName']})
def cloudtrail_create_or_delete_anything(rec):
    """Trigger an alert when anything is created"""
    return in_set(rec['detail']['eventName'], {
        'Create*',
        'Delete*'
    })

@rule(logs=['cloudtrail:v1.04', 'cloudtrail:v1.05'],
      outputs=['aws-s3:main'])
def cloudtrail_s3_source_create_or_delete(rec):
    return in_set(rec['eventName'], {
        'Create*',
        'Delete*'
    })
