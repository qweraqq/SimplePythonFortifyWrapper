#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import datetime
from SSCClient.core import SSCClient
from SSCClient.utils import  func_extract_all_project_names
from collections import defaultdict

if __name__ == "__main__":
    ssc_client = SSCClient("https://192.168.1.1/ssc")
    # ssc_client.set_auth_token("OWQzZDVkM2YtZWFmNS00ZGIxLWJkZmQtMTMwZDdkMzhmZmU0")
    ssc_client.set_auth_cookie("E58BC67EEB87A6BAFE32778A2C9CB395")
    project_version_mapping = ssc_client.func_get_project_version_dict()

    id_list = []
    print("project,version,critical,high,medium,low,noOfFiles, totalLOC,execLOC,elapsedTime,lastScanData")
    for project_info, version_list in project_version_mapping.items():
        for version_info in version_list:
            version_id = version_info.id
            id_list.append(version_id)
            # 获取扫描结果
            r = ssc_client.func_get_issue_count_by_id(version_id=version_id, showsuppressed="true", showhidden="true")
            if len(r) == 0:
                print("{},{},,,,,,,,,".format(project_info.name, version_info.name))
                continue
            scan_result = defaultdict(int)
            for _ in r:
                scan_result[_['id']] = _['totalCount']
            
            # 获取最后一次扫描任务执行信息
            start = 0
            while True:
                r = ssc_client.func_get_artifact_info(version_id, start)
                if r[0]['_embed']['scans'][0] is None:
                    start += 1
                    continue
                noOfFiles = r[0]['_embed']['scans'][0]['noOfFiles']
                totalLOC = r[0]['_embed']['scans'][0]['totalLOC']
                execLOC = r[0]['_embed']['scans'][0]['execLOC']
                elapsedTime =r[0]['_embed']['scans'][0]['elapsedTime']
                tmp = elapsedTime.split(':')
                if len(tmp) == 2:
                    elapsedTime = datetime.timedelta(minutes=float(elapsedTime.split(':')[0]), seconds=float(elapsedTime.split(':')[1]))
                if len(tmp) == 3:
                    elapsedTime = datetime.timedelta(hours=float(elapsedTime.split(':')[0]), minutes=float(elapsedTime.split(':')[1]), seconds=float(elapsedTime.split(':')[2]))
                lastScanData = r[0]['lastScanDate']
                lastScanData = datetime.datetime.strptime(lastScanData.split('.')[0], "%Y-%m-%dT%H:%M:%S")
                print("{},{},{},{},{},{},".format(project_info.name, version_info.name, scan_result['Critical'], scan_result['High'],scan_result['Medium'], scan_result['Low']),end='')
                print("{},{},{},{},{}".format(noOfFiles, totalLOC, execLOC, elapsedTime.total_seconds(), lastScanData))
                break
    
    # 为用户增加访问project version的权限
    username = "firstname2"
    for version_id in id_list:
        ssc_client.func_suppress_all_issues_by_folder(2, "Low")
        # ssc_client.func_add_ladpuser_to_projectverion_by_user_name(version_id, username)