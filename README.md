# 基于python3 requests的Fortify SSC api调用封装
没有找到Fortify SSC可以使用的python restful api封装，分享一下几个api的使用封装(主要是LDAP用户管理相关的api)

仅在Fortify SSC 19.1.0测试过

### 依赖
- python3
- requests

### 使用方式
```python
from SSCClient.core import SSCClient
from SSCClient.utils import  func_extract_all_project_names

ssc_client = SSCClient("http://127.0.0.1:8080/ssc")

# Authorization: cookie or FortifyToken
ssc_client.set_auth_cookie("E75A5DE50330739BEAE8D495D25912E1")  # JSESSIONID

ssc_client.set_auth_token("N2QzYjZjMzUtYmU3Mi00MTc2LTg4ZDEtYjZlOWY3MDE5YzVj") # Fortify Token


# 获取当前Fortify SSC支持的所有roles, SSC默认为["admin", "appsectester", "developer", "manager", "securitylead", "viewonly", "wiesystem"]
ssc_client.func_get_fortify_roles()

# 添加一个LDAP用户至SSC, 默认权限为viewonly
user_info = ssc_client.func_get_non_fortify_ldap_user_info("firstname.lastname")
r = ssc_client.func_add_roles_to_ldap_user(user_info, ["viewonly"])

# 从SSC中删除一个LDAP用户
ssc_client.func_del_ldap_user_by_username("firstname.lastname")

# 更新一个LDAP用户的权限
ssc_client.func_update_roles_for_ldap_user_by_user_name("firstname.lastname",["new_role1", "new_roles2"])

# 获取当前所有的project(application)
project_version_mapping = ssc_client.func_get_project_version_dict()
print(func_extract_all_project_names(project_version_mapping))

# 获取LDAP用户当前的version访问权限
ssc_client.func_get_project_version_by_ldap_user_name("firstname.lastname")

# 为LDAP用户增加version的访问权限
ssc_client.func_add_project_version_auth_by_ldap_user_name("firstname.lastname", [1, 2, 3])  # 1,2,3表示version id


# 获取扫描结果
project_version_mapping = ssc_client.func_get_project_version_dict()
ga_release_mapping = {}
# 根据实际要求filter出需要获取结果的project+version
for _ in project_version_mapping.keys():
    for tmp in project_version_mapping[_]:
        if tmp.name == "Your_Version": # custom
            ga_release_mapping[_.name] = tmp.id

version_id = ga_release_mapping[project_name]
r = ssc_client.func_get_issue_count_by_id(version_id=version_id, showsuppressed="true", showhidden="true")
result = defaultdict(int)
for _ in r:
    result[_['id']] = _['totalCount']
print("{},{},{},{},{}".format(project_name, result['Critical'], result['High'],result['Medium'], result['Low']))
```
