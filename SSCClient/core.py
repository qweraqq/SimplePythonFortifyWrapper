#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import absolute_import
import requests
import json
import logging
from collections import defaultdict
from .structs import Version_Info, Project_Info
from .utils import *

logger = logging.getLogger(__name__)


class SSCClient(object):
    """ Major component of python3 wrapper for func_simple_sca_cli ssc restful api
    Test on Fortify SSC 19.1.0
    更多注释
    """
    _auth_cookie = ""
    _ssc_url = ""  # Fortify SSC的地址
    _ssc_api_base = ""  # _SSC_URL + "/api/v1"
    # 以下只是Fortify SSC默认的roles列表
    _ssc_roles_list = ["admin", "appsectester", "developer",
                       "manager", "securitylead", "viewonly", "wiesystem"]
    _session = None  # requests的session
    _requests_headers = {"Accept": "application/json",
                         "Content-Type": "application/json;charset=UTF-8"}
    _requests_cookies = {"JSESSIONID": _auth_cookie}
    _project_version_mapping = defaultdict(set)

    def __init__(self, url=None):
        logger.info('init with url: {0}'.format(url))
        self._ssc_url = url
        self._ssc_api_base = self._ssc_url + "/api/v1"
        self._session = requests.session()
        self._requests_cookies = None

    def __del__(self):
        if self._session is not None:
            self._session.close()

    def set_auth_cookie(self, auth_cookie=None):
        self._auth_cookie = auth_cookie
        self._requests_cookies = {"JSESSIONID": self._auth_cookie}

    def set_auth_token(self, auth_token=None):
        self._requests_headers['Authorization'] = "FortifyToken {}".format(auth_token)


    def func_get_fortify_roles(self):
        """
        获取fortify当前的roles列表
        side effect: 更新现有的roles_list
        :return: fortify当前的roles列表
        """
        url = self._ssc_api_base + "/roles"
        r = self._session.get(
            url, headers=self._requests_headers, cookies=self._requests_cookies)
        logging.debug(
            "func_get_fortify_roles\r\nraw response: {}".format(r.content))
        if r.status_code != 200:
            logging.error("func_get_fortify_roles error getting roles")
            return None
        roles_list = []
        for _ in json.loads(r.content)["data"]:
            roles_list.append(_["id"])
        self._ssc_roles_list = roles_list
        return roles_list

    def func_get_fortify_ldap_user_info_by_name(self, user_name):
        """
        根据用户名查询条件获取当前Fortify已有用户的信息
        限制条件: 必须是精准匹配用户名，也就是有且仅有一个匹配结果
        :param user_name: 精准的用户名
        :return: 用户信息的json, 如果失败(包含多个匹配或无匹配)返回None
        """
        payloads = {"limit": 2, "start": "0", "q": user_name}
        url = self._ssc_api_base + '/ldapObjects'
        r = self._session.get(url, headers=self._requests_headers,
                              cookies=self._requests_cookies, params=payloads)
        logging.debug("func_get_fortify_ldap_user_info_by_name {}\r\nraw response: {}".format(
            user_name, r.content))
        if r.status_code != 200:
            logging.error(
                "func_get_fortify_ldap_user_info_by_name error getting user info")
            return None
        user_info_from_ssc = json.loads(r.content)
        if user_info_from_ssc["count"] > 1:
            logging.error(
                "func_get_fortify_ldap_user_info_by_name: more than one user matched for {}".format(user_name))
            return None
        if user_info_from_ssc["count"] < 1:
            logging.error(
                "func_get_fortify_ldap_user_info_by_name: no user matched for {}".format(user_name))
            return None
        return user_info_from_ssc["data"][0]

    def func_get_fortify_ldap_user_info_by_id(self, user_id):
        """
        根据用户名查询条件获取当前Fortify已有用户的信息
        :param user_id: 用户id
        :return: 用户信息的json, 如果失败(包含多个匹配或无匹配)返回None
        """
        url = self._ssc_api_base + '/ldapObjects/' + str(user_id)
        r = self._session.get(
            url, headers=self._requests_headers, cookies=self._requests_cookies)
        logging.debug("func_get_fortify_ldap_user_info_by_id {} \r\nraw response: {}".format(
            user_id, r.content))
        if r.status_code != 200:
            logging.error(
                "func_get_fortify_ldap_user_info_by_id error getting user info")
            return None
        user_info_from_ssc = json.loads(r.content)
        return user_info_from_ssc["data"]

    def func_get_fortify_ldap_user_id_by_name(self, user_name):
        """
        根据用户名查询条件获取当前Fortify已有用户的id
        限制条件: 必须是精准匹配用户名，也就是有且仅有一个匹配结果
        :param user_name: 精准匹配用户名
        :return: 用户id, 如果失败返回None
        """
        r = self.func_get_fortify_ldap_user_info_by_name(user_name)
        if r is None:
            return None
        else:
            return int(r["_href"].split("/")[-1])

    def func_get_non_fortify_ldap_user_info(self, user_name):
        url = self._ssc_api_base + '/ldapObjects'
        payloads = {"ldaptype": "USER", "limit": 2, "q": user_name, "start": 0}
        r = self._session.get(url, headers=self._requests_headers,
                              cookies=self._requests_cookies, params=payloads)
        logging.debug("func_get_non_fortify_ldap_user_info {}\r\nraw response: {}".format(
            user_name, r.content))
        if r.status_code != 200:
            logging.error(
                "func_get_non_fortify_ldap_user_info error getting user info")
            return None
        user_info_from_ssc = json.loads(r.content)["data"]
        if len(user_info_from_ssc) > 1:
            logging.error(
                "func_get_non_fortify_ldap_user_info: more than one user matched for {}".format(user_name))
            return None
        if len(user_info_from_ssc) < 1:
            logging.error(
                "func_get_non_fortify_ldap_user_info: no user matched for {}".format(user_name))
            return None
        return user_info_from_ssc[0]

    def func_add_roles_to_ldap_user(self, user_info, roles=['viewonly']):
        """
        为现在无法登陆的ldap用户添加权限，从而使得ldap用户可以访问fortify ssc
        默认情况下ldap用户的roles为null，不能登陆fortify ssc
        :param user_info:  调用func_get_ldap_user返回的userinfo的json
        :param roles: 权限的string list, 默认只有'view only', 会做白名单校验
        默认SSC_ROLES_LIST = ["admin", "appsectester", "developer", "manager", "securitylead", "viewonly", "wiesystem"]
        :return: True表示添加成功, False表示添加失败
        """
        url = self._ssc_api_base + "/ldapObjects"
        user_info["roles"] = []
        # role validation
        for _ in roles:
            if _ not in self._ssc_roles_list:
                logging.error("Role {} not allowed".format(_))
            else:
                user_info["roles"].append({"id": _})
        if len(user_info["roles"]) < 1:
            user_info["roles"] = [{"id": "viewonly"}]
        logging.debug("Adding user to Fortify SSC: \r\n {}".format(user_info))
        r = self._session.post(url, headers=self._requests_headers,
                               cookies=self._requests_cookies, json=user_info)
        if r.status_code == 201:  # created
            logging.debug(
                "User {} added successfully".format(user_info['name']))
            return True
        else:
            logging.error("Failed adding user {}, error message \r\n {}".format(
                user_info['name'], r.content))
            return False

    def func_del_ldap_user_by_id(self, user_id):
        """
        通过user_id删除用户
        :param user_id:
        :return: True表示删除成功, False表示删除成功
        """
        url = self._ssc_api_base + "/ldapObjects"
        payloads = {"ids": user_id}
        r = self._session.delete(
            url, headers=self._requests_headers, cookies=self._requests_cookies, params=payloads)
        logging.debug(
            "func_del_ldap_user_by_id {}\r\nraw response {}".format(user_id, r.content))
        if r.status_code == 200:
            return True
        else:
            logging.error("Error func_del_ldap_user_by_id {}".format(user_id))
            return False

    def func_del_ldap_user_by_username(self, user_name):
        """
        通过user_name删除用户
        限制条件: 必须是精准匹配用户名，也就是有且仅有一个匹配结果
        :param user_name: 精准匹配用户名
        :return: True表示删除成功, False表示删除成功
        """
        user_id = self.func_get_fortify_ldap_user_id_by_name(user_name)
        if user_id is None:
            return False
        return self.func_del_ldap_user_by_id(user_id)

    def func_update_roles_for_ldap_user_by_user_id(self, user_id, roles=['viewonly']):
        """
        为现有ldap用户更改权限
        :param user_id:
        :param roles: 权限的string list, 默认只有'view only', 会做白名单校验
        默认SSC_ROLES_LIST = ["admin", "appsectester", "developer", "manager", "securitylead", "viewonly", "wiesystem"]
        :return: True表示更新成功, False表示更新失败
        """
        url = self._ssc_api_base + "/ldapObjects/" + str(user_id)
        user_info = self.func_get_fortify_ldap_user_info_by_id(user_id)
        if user_info is None:
            logging.error(
                "func_update_roles_for_ldap_user_by_user_id failed: invalid user id {}".format(user_id))
            return False
        user_info["roles"] = []
        # role validation
        for _ in roles:
            if _ not in self._ssc_roles_list:
                logging.error("Role {} not allowed".format(_))
                return False
            else:
                user_info["roles"].append({"id": _})
        if len(user_info["roles"]) < 1:
            user_info["roles"] = [{"id": "viewonly"}]
        logging.debug(
            "Updating user id {} to Fortify SSC: \r\n {}".format(user_id, user_info))
        r = self._session.put(url, headers=self._requests_headers,
                              cookies=self._requests_cookies, json=user_info)
        logging.debug("func_update_roles_for_ldap_user_by_user_id {} \r\nraw response {}".format(
            user_id, r.content))
        if r.status_code == 200:  # updated
            logging.debug(
                "func_update_roles_for_ldap_user_by_user_id {} updated successfully".format(user_id))
            return True
        else:
            logging.error("Failed: func_update_roles_to_ldap_user_by_user_id {}, error message \r\n {}".
                          format(user_id, r.content))
            return False

    def func_update_roles_for_ldap_user_by_user_name(self, user_name, roles=['viewonly']):
        """
        为现有ldap用户更改权限
        限制条件: 必须是精准匹配用户名，也就是有且仅有一个匹配结果
        :param user_name: 精准匹配用户名
        :param roles: 权限的string list, 默认只有'view only', 会做白名单校验
        默认SSC_ROLES_LIST = ["admin", "appsectester", "developer", "manager", "securitylead", "viewonly", "wiesystem"]
        :return: True表示更新成功, False表示更新失败
        """
        user_id = self.func_get_fortify_ldap_user_id_by_name(user_name)
        if user_id is None:
            logging.error(
                "func_update_roles_for_ldap_user_by_user_name failed: invalid user name {}".format(user_name))
            return False
        return self.func_update_roles_for_ldap_user_by_user_id(user_id, roles)

    def func_get_project_version_dict(self):
        """
        Fortify中的project对应页面上的application
        Version对应页面上的version
        Fortify对于project和version的管理没有做区分(至少在api上是这样的)
        这个函数的功能是返回一个dict, 得到{project_info1:[version_info1_1, version_info1_2], ...}
        :return: project与version对应的dict 得到{project_info1:[version_info1_1, version_info1_2], ...}
        """
        url = self._ssc_api_base + "/projectVersions"
        payloads = {"limit": 1, "start": 0, "includeInactive": True, "myAssignedIssues": False, "orderby": "id",
                    "fields": "id,name,project,active,committed,owner,description,creationDate,currentState"}
        r = self._session.get(url, headers=self._requests_headers,
                              cookies=self._requests_cookies, params=payloads)
        logging.debug(
            "func_get_project_version_dict get counts\r\nraw content: {}".format(r.content))
        if r.status_code != 200:
            logging.error(
                "func_get_project_version_dict failed: {}".format(r.content))
            return self._project_version_mapping

        project_version_count = int(json.loads(r.content)["count"])
        payloads = {"limit": project_version_count, "start": 0, "includeInactive": True, "myAssignedIssues": False,
                    "orderby": "id",
                    "fields": "id,name,project,active,committed,owner,description,creationDate,currentState"}
        r = self._session.get(url, headers=self._requests_headers,
                              cookies=self._requests_cookies, params=payloads)
        logging.debug(
            "func_get_project_version_dict get full list\r\nraw content: {}".format(r.content))
        if r.status_code != 200:
            logging.error(
                "func_get_project_version_dict failed: {}".format(r.content))
            return self._project_version_mapping

        data = json.loads(r.content)["data"]
        self._project_version_mapping = defaultdict(set)
        for _ in data:
            project_info = Project_Info(
                int(_["project"]["id"]), _["project"]["name"])
            version_info = Version_Info(int(_["id"]), _["name"])
            self._project_version_mapping[project_info].add(version_info)

        logging.debug("func_get_project_version_dict raw_mapping\r\n{}".format(
            self._project_version_mapping))
        return self._project_version_mapping

    def func_update_project_version_dict(self):
        self.func_get_project_version_dict()

    def func_get_project_version_by_user_id(self, user_id):
        """
        通过user_id获取用户在Fortify SSC用户管理ACCESS中的列表
        返回形式为project_info: version_info_list的形式
        :param user_id:
        :return: 用户权限project与version对应的dict 得到{project_info1:[version_info1_1, version_info1_2], ...}
        """
        url = self._ssc_api_base + "/authEntities/" + \
            str(user_id) + "/projectVersions"
        payloads = {"limit": 1, "start": 0}
        r = self._session.get(url, headers=self._requests_headers,
                              cookies=self._requests_cookies, params=payloads)
        logging.debug(
            "func_get_project_version_by_user_id get counts\r\nraw content: {}".format(r.content))
        if r.status_code != 200:
            logging.error(
                "func_get_project_version_by_user_id failed: {}".format(r.content))
            return None

        project_version_count = int(json.loads(r.content)["count"])
        ret_dict = defaultdict(set)
        payloads = {"limit": project_version_count, "start": 0}
        r = self._session.get(url, headers=self._requests_headers,
                              cookies=self._requests_cookies, params=payloads)
        data = json.loads(r.content)["data"]
        for _ in data:
            project_info = Project_Info(
                int(_["project"]["id"]), _["project"]["name"])
            version_info = Version_Info(int(_["id"]), _["name"])
            ret_dict[project_info].add(version_info)

        logging.debug(
            "func_get_project_version_by_user_id raw_mapping\r\n{}".format(ret_dict))
        return ret_dict

    def func_get_project_version_by_ldap_user_name(self, user_name):
        """
        通过user_name获取用户在Fortify SSC用户管理ACCESS中的列表
        限制user_name必须精准，有且仅有1个
        返回形式为project_info: version_info_list的形式
        :param user_name:
        :return: 用户权限project与version对应的dict 得到{project_info1:[version_info1_1, version_info1_2], ...}
        """
        user_id = self.func_get_fortify_ldap_user_id_by_name(user_name)
        if user_id is None:
            return None
        return self.func_get_project_version_by_user_id(user_id)

    def func_add_project_version_auth_by_user_id(self, user_id, version_ids):
        """
        为当前用户添加可以access的version列表
        SSC界面上Access中的add按钮
        :param user_id:
        :param version_ids: list, 需要添加访问权限的version id列表，比如[1,2,3]
        :return: True表示成功, False表示失败
        """
        url = self._ssc_api_base + "/authEntities/" + \
            str(user_id) + "/projectVersions/action"
        already_auth_versions = func_extract_all_version_ids(
            self.func_get_project_version_by_user_id(user_id))
        if len(set(already_auth_versions).intersection(set(version_ids))) > 0:
            logging.error("func_add_project_version_auth_by_user_id error: conflict version ids {}".
                          format(set(already_auth_versions).intersection(set(version_ids))))
            return False

        # TODO: 增加version_ids的有效性判断
        payloads = {"ids": version_ids, "type": "assign"}
        r = self._session.post(url, headers=self._requests_headers,
                               cookies=self._requests_cookies, json=payloads)
        logging.debug("func_add_project_version_auth_by_user_id {} version ids {}\r\nraw response{}".
                      format(user_id, version_ids, r.content))
        if r.status_code == 200:
            return True
        else:
            return False

    def func_add_project_version_auth_by_ldap_user_name(self, user_name, version_ids):
        """
        为当前用户添加可以access的version列表
        SSC界面上Access中的add按钮
        :param user_name:
        :param version_ids: list, 需要添加访问权限的version id列表，比如[1,2,3]
        :return: True表示成功, False表示失败
        """
        user_id = self.func_get_fortify_ldap_user_id_by_name(user_name)
        if user_id is None:
            logging.error(
                "func_add_project_version_auth_by_ldap_user_name {} invalid user name".format(user_name))
            return False
        return self.func_add_project_version_auth_by_user_id(user_id, version_ids)

    def func_get_issue_count_by_id(self, version_id, showsuppressed="false", showhidden="false"):
        """
        根据projectVersionId获取结果
        """
        url = self._ssc_api_base + \
            "/projectVersions/{}/issueGroups".format(version_id)
        payloads = {"groupingtype": "FOLDER", "filterset": "a243b195-0a59-3f8b-1403-d55b7a7d78e6",
                    "showhidden": showhidden, "showremoved": "false", "showshortfileNames": "false", "showsuppressed": showsuppressed}
        r = self._session.get(url, headers=self._requests_headers,
                              cookies=self._requests_cookies, params=payloads)
        if r.status_code == 200:
            data = json.loads(r.content)['data']
            return data
        else:
            return None
    
    def func_delete_by_id(self, version_id):
        """
        根据id删除project_version
        成功返回true, 失败返回false
        """
        url = self._ssc_api_base + "/projectVersions/{}?hideProgress=true"
        url = url.format(version_id)
        r = self._session.delete(url, headers=self._requests_headers, cookies=self._requests_cookies)
        if r.status_code == 200:
            return True
        else:
            return False

    def func_get_artifact_info(self, version_id):
        url = self._ssc_api_base + "/projectVersions/{}/artifacts?hideProgress=true&embed=scans&limit=1&start=0"
        url = url.format(version_id)
        r = self._session.get(url, headers=self._requests_headers, cookies=self._requests_cookies)
        if r.status_code == 200:
            data = json.loads(r.content)['data']
            return data
        else:
            return None
