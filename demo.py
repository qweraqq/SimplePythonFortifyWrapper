#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import datetime
from SSCClient.core import SSCClient
from SSCClient.utils import  func_extract_all_project_names
from collections import defaultdict

if __name__ == "__main__":
    ssc_client = SSCClient("http://192.168.22.130:8080/ssc")
    ssc_client.set_auth_token("N2QzYjZjMzUtYmU3Mi00MTc2LTg4ZDEtYjZlOWY3MDE5YzVj")
    project_version_mapping = ssc_client.func_get_project_version_dict()

    print("project,version,critical,high,medium,low,noOfFiles, totalLOC,execLOC,elapsedTime,lastScanData")
    for project_info, version_list in project_version_mapping.items():
        for version_info in version_list:
            version_id = version_info.id
            # 获取扫描结果
            r = ssc_client.func_get_issue_count_by_id(version_id=version_id, showsuppressed="true", showhidden="true")
            if len(r) == 0:
                print("{},{},,,,,,,,,".format(project_info.name, version_info.name))
                continue
            scan_result = defaultdict(int)
            for _ in r:
                scan_result[_['id']] = _['totalCount']
            
            # 获取最后一次扫描任务执行信息
            r = ssc_client.func_get_artifact_info(version_id)
            noOfFiles = r[0]['_embed']['scans'][0]['noOfFiles']
            totalLOC = r[0]['_embed']['scans'][0]['totalLOC']
            execLOC = r[0]['_embed']['scans'][0]['execLOC']
            elapsedTime =r[0]['_embed']['scans'][0]['elapsedTime']
            elapsedTime = datetime.timedelta(hours=float(elapsedTime.split(':')[0]), seconds=float(elapsedTime.split(':')[1]))
            lastScanData = r[0]['lastScanDate']
            lastScanData = datetime.datetime.strptime(lastScanData.split('.')[0], "%Y-%m-%dT%H:%M:%S")
            print("{},{},{},{},{},{},".format(project_info.name, version_info.name, scan_result['Critical'], scan_result['High'],scan_result['Medium'], scan_result['Low']),end='')
            print("{},{},{},{},{}".format(noOfFiles, totalLOC, execLOC, elapsedTime.total_seconds(),lastScanData))