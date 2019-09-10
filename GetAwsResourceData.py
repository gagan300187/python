from datetime import datetime
import pandas as pd
import os
import boto3
import json
import logging


AWSResources = ['ec2data','securitygroup']
Regions = ["eu-central-1", "us-west-2"]
DataDir = {"securitygroup": "securitygroupdata/data/", "ec2data": "ec2data/data/"}
BaselineDir = {"securitygroup": "securitygroupdata/baseline/", "ec2data": "ec2data/baseline/"}
today = datetime.now()
pd.set_option('display.max_columns', None)
pd.set_option('display.expand_frame_repr', False)
pd.set_option('max_colwidth', -1)
pd.options.display.max_rows=10000

logging.basicConfig(filename="AwsScript" + today.strftime('%Y%m%d') + ".log",
                    format='%(asctime)s %(message)s', datefmt='%d/%m/%Y %H:%M:%S', level=logging.INFO,
                    filemode='w')
logger=logging.getLogger()


def CheckBaseline(Resource,regloop):
    BaselineFile = BaselineDir[Resource] + regloop + ".json"
    if not os.path.exists(BaselineFile):
        logger.critical("Baseline file not present:" + BaselineFile)
        return("Missing file: " + BaselineFile)
    else:
        logger.info("File OK:" + BaselineFile)
        return ("File OK:\t" + BaselineFile)

def CreateBaseline(Resource,regloop):
    BaselineDir = PrepareBaselineDir(Resource)

    if Resource == "ec2data":
        BaselineFile = BaselineDir + "/" + regloop + ".json"
        ec2 = boto3.client('ec2', region_name=regloop)
        ec2list = ec2.describe_instances()
        ec2_data = {}
        ec2_list = []
        for i in ec2list['Reservations']:
            for j in i['Instances']:
                ec2_data['InstanceId'] = j['InstanceId']
                ec2_data['InstanceType'] = j['InstanceType']
                ec2_data['State'] = j['State']['Name']
                ec2_list.append(dict(ec2_data))
        json_data = json.dumps(ec2_list)
        with open(BaselineFile, 'w') as json_file:
            json_file.write(json_data)
        json_file.close()
        logger.info("Baseline file created for:" +BaselineFile )

    if Resource == "securitygroup":
        BaselineFile = BaselineDir + "/" + regloop + ".json"
        SgData = {}
        SgDetail = []
        ec2 = boto3.client('ec2', region_name=regloop)
        ec2list = ec2.describe_security_groups()
        for i in ec2list['SecurityGroups']:
            SgData['Name'] = i['GroupName']
            SgData['GroupId'] = i['GroupId']
            SgRuleList = []
            for ir in i['IpPermissions']:
                SgRuleDetail = {}
                if 'FromPort' in ir:
                    SgRuleDetail['FromIp'] = str(ir['FromPort'])
                    SgAllowedIps = []
                    for ips in ir['IpRanges']:
                        SgAllowedIps.append(ips['CidrIp'])
                    for ips in ir['UserIdGroupPairs']:
                        SgAllowedIps.append(ips['GroupId'])
                    SgRuleDetail['IpRange'] = SgAllowedIps
                    SgRuleDetail['ToPort'] = str(ir['ToPort'])
                    SgRuleList.append(SgRuleDetail)
                SgData['Rules'] = SgRuleList
            SgDetail.append(dict(SgData))
        json_data = json.dumps(SgDetail)
        logger.info(json_data)
        with open(BaselineFile, 'w') as json_file:
            json_file.write(json_data)
        json_file.close()
        logger.info("Baseline file created for:" + BaselineFile)


def PrepareDataDir(Resource):
    ddirname = DataDir[Resource] + today.strftime('%Y%m%d')
    if not os.path.exists(ddirname):
        os.mkdir(ddirname)
        logger.info("data directory Created: " + ddirname)
    else:
        logger.info("Directory Already exists: " + ddirname)
    return ddirname

def PrepareBaselineDir(Resource):
    ddirname = BaselineDir[Resource]
    if not os.path.exists(ddirname):
        logger.critical("Baseline Dir is not present.")
        os.mkdir(ddirname)
        logger.info("Created:" + ddirname)
    else:
        logger.info("Directory Already exists:" + ddirname)
    return ddirname

def GetEc2Data():
    logger.info("collecting latest Ec2 data.")
    for regloop in Regions:
        datadir = PrepareDataDir("ec2data")
        ResultFile = datadir + "/" + regloop + ".json"
        ec2 = boto3.client('ec2', region_name=regloop)
        ec2list = ec2.describe_instances()
        ec2_data = {}
        ec2_list = []
        for i in ec2list['Reservations']:
            for j in i['Instances']:
                ec2_data['InstanceId'] = j['InstanceId']
                ec2_data['InstanceType'] = j['InstanceType']
                ec2_data['State'] = j['State']['Name']
                ec2_list.append(dict(ec2_data))
        json_data = json.dumps(ec2_list)
        with open(ResultFile, 'w') as json_file:
            json_file.write(json_data)
        json_file.close()
        logger.info("Data collection complete: " + ResultFile)

def GetSgData ():
    logger.info("Collecting data for AWS SecurityGroups.")
    for regloop in Regions:
        datadir = PrepareDataDir("securitygroup")
        ResultFile = datadir + "/" + regloop + ".json"
        SgData = {}
        SgDetail = []
        ec2 = boto3.client('ec2', region_name=regloop)
        ec2list = ec2.describe_security_groups()
        for i in ec2list['SecurityGroups']:
            SgData['Name'] = i['GroupName']
            SgData['GroupId'] = i['GroupId']
            SgRuleList = []
            for ir in i['IpPermissions']:
                SgRuleDetail = {}
                if 'FromPort' in ir:
                    SgRuleDetail['FromIp'] = str(ir['FromPort'])
                    SgAllowedIps = []
                    for ips in ir['IpRanges']:
                        SgAllowedIps.append(ips['CidrIp'])
                    for ips in ir['UserIdGroupPairs']:
                        SgAllowedIps.append(ips['GroupId'])
                    SgRuleDetail['IpRange'] = SgAllowedIps
                    SgRuleDetail['ToPort'] = str(ir['ToPort'])
                    SgRuleList.append(SgRuleDetail)
                SgData['Rules'] = SgRuleList
            #print(SgData)
            SgDetail.append(dict(SgData))
        #print(SgDetail)
        json_data = json.dumps(SgDetail)
        logger.info(json_data)
        #print(json_data)
        with open(ResultFile, 'w') as json_file:
            json_file.write(json_data)
        json_file.close()
        logger.info("Data Collection Complete: " + ResultFile)

def FetchSgBaseLineData (Region):
    DataFile = BaselineDir["securitygroup"]  + Region + ".json"
    logger.info("Reading SecurityGroup Baseline file: " + DataFile)
    with open(DataFile) as json_file:
        data = json.load(json_file)
        BaseData = {}
        BaseSgData = []
        for i in data:
            Gid = i['GroupId']
            Gname = i['Name']
            for j in i['Rules']:
                for k in j['IpRange']:
                    BaseData['AllowedIp'] = k
                    BaseData['Port'] = (j['ToPort'])
                    BaseData['SgId'] = Gid
                    BaseData['SgName'] = Gname
                    BaseSgData.append(dict(BaseData))
    logger.info("File reading and Data load complete.")
    return (BaseSgData)

def FetchSgCurrentData(Region):
    CurrentFile = DataDir["securitygroup"] + today.strftime('%Y%m%d') + "/" + Region + ".json"
    logger.info("Reading SecurityGroup Data file: " + CurrentFile)
    with open(CurrentFile) as json_file:
        data = json.load(json_file)
        CurrentData = {}
        CurrentSgData = []
        for i in data:
            Gid = i['GroupId']
            Gname = i['Name']
            for j in i['Rules']:
                for k in j['IpRange']:
                    # print(k)
                    CurrentData['AllowedIp'] = k
                    CurrentData['Port'] = (j['ToPort'])
                    CurrentData['SgId'] = Gid
                    CurrentData['SgName'] = Gname
                    CurrentSgData.append(dict(CurrentData))
    logger.info("File read and data load complete")
    return CurrentSgData

def CompareSgData ():
    FinalResult = pd.DataFrame()
    for region in Regions:
        BaseSgData=FetchSgBaseLineData(region)
        CurrentSgData=FetchSgCurrentData(region)
        logger.info("Comparing SecurityGroup data with baseline. Data file.")
        #print(BaseSgData)
        #print(CurrentSgData)
        df1 = pd.DataFrame(BaseSgData)
        df2 = pd.DataFrame(CurrentSgData)
        #print(df1)
        #print(df2)
        df_merge_col2 = pd.merge(df1, df2, on=['SgId', 'Port', 'AllowedIp'], how='outer')
        df_merge_col2.columns = ['Allowed_IP', 'Port_Number', 'SecurityGroup_Id', 'Baseline', 'Current']
        res1 = df_merge_col2[df_merge_col2.isna().any(axis=1)]
        res1 = res1.fillna('Missing')
        print(res1)
        if res1.empty:
            logger.info("No Changes found.")
        else:
            logger.critical("Changes found.")
            res1['Region']=region
            print(res1)
            FinalResult = pd.concat([FinalResult, res1])
        FinalResult.to_csv('SecurityGroup_changes.csv')

def FetchEc2BaseLineData(Region):
    DataFile = BaselineDir['ec2data'] + Region + ".json"
    logger.info("Reading baseline file for EC2: " + DataFile)
    f1 = open(DataFile, 'r').read()
    BaseEc2Data = json.loads(f1)
    logger.info("File read and data load complete.")
    return (BaseEc2Data)

def FetchEc2CurrentData(Region):
    CurrentFile = DataDir["ec2data"] + today.strftime('%Y%m%d') + "/" + Region + ".json"
    logger.info("Reading Data file for EC2: " + CurrentFile)
    f1 = open(CurrentFile,'r').read()
    CurrentEc2Data = json.loads(f1)
    logger.info("File read and data load complete")
    return (CurrentEc2Data)

def CompareEc2Data():
    FinalResult=pd.DataFrame()
    for region in Regions:
        BaseEc2Data=FetchEc2BaseLineData(region)
        CurrentEc2Data=FetchEc2CurrentData(region)
        logger.info("Comparing Ec2 data with baseline. Data file." )
        df1 = pd.DataFrame(BaseEc2Data)
        df2 = pd.DataFrame(CurrentEc2Data)
        df_merge_col2 = pd.merge(df1, df2, on=['InstanceId'], how='outer')
        df_merge_col2.columns = ['InstanceId', 'Baseline_Type', 'Baseline_state', 'Current_Type', 'Current_state']
        res1 = df_merge_col2.query('Baseline_Type != Current_Type or Baseline_state != Current_state')
        if res1.empty:
            logger.info("No Changes found.")
            #FinalResult=pd.merge(FinalResult,res1)
        else:
            logger.critical("Changes found.")
            res1 = res1.fillna('Missing')
            res1['Region']=region
            FinalResult=pd.concat([FinalResult,res1])
        FinalResult.to_csv('Ec2_changes.csv')

def main():
    # Check is baseline is present or not
    logger.info("Checking if Baseline is present or not")
    for resource in AWSResources:
        for region in Regions:
            logger.info("Checking for: " + resource + "in: " + region)
            BlCheckResult=CheckBaseline(resource,region)
            if "File OK" not in BlCheckResult:
                logger.critical(resource + region + " File missing... creating now.")
                CreateBaseline(resource,region)
                logger.info("Baseline created")
            else:
                logger.info("Baseline Present for" + resource + ":" + region)

    # Fetch the latest data for Ec2 and Securitygroup
    GetEc2Data()
    GetSgData()

    # COmpare the data with baseline:
    CompareEc2Data()
    CompareSgData()

main()