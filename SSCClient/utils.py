#!/usr/bin/env python3
# -*- coding: utf-8 -*-


def func_extract_all_project_ids(project_version_mapping):
    """
    :param project_version_mapping:
    :return: project id list
    """
    ids = []
    for _ in project_version_mapping.keys():
        ids.append(_.id)
    return ids


def func_extract_all_project_names(project_version_mapping):
    """

    :param project_version_mapping:
    :return:
    """
    names = []
    for _ in project_version_mapping.keys():
        names.append(_.name)
    return names


def func_extract_all_version_ids(project_version_mapping):
    """

    :param project_version_mapping:
    :return: version id list
    """
    ids = []
    for tmp in project_version_mapping.values():
        ids.extend([_.id for _ in tmp])
    return ids
