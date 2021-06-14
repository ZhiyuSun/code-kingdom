# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

import collections
import copy

from django.conf import settings
from django.utils.translation import ugettext as _
from six.moves import map

from bkmonitor.drf_non_orm.exceptions import CustomException
from bkmonitor.resource import resource
from bkmonitor.utils.cache import CacheType, using_cache
from bkmonitor.utils.common_utils import DictObj, host_key, ignored
from bkmonitor.utils.country import CHINESE_PROVINCES, COUNTRIES, ISP_LIST
from bkmonitor.utils.host import Host
from bkmonitor.utils.sdk_client import client
from common.log import logger
from core.drf_resource import api
from monitor.constants import AGENT_STATUS


@using_cache(CacheType.CC)
def biz_model(cc_biz_id):
    nodes = topo_tree(cc_biz_id)
    if nodes:
        nodes = nodes["child"]
    else:
        return

    model = [
        {
            "bk_obj_id": "module",
            "bk_obj_name": "模块"
        },
        {
            "bk_obj_id": "set",
            "bk_obj_name": "集群"
        },
        {
            "bk_obj_id": "biz",
            "bk_obj_name": "业务"
        }
    ]

    while nodes:
        if nodes[0]["bk_obj_id"] not in ["module", "set", "biz"]:
            model.append(dict(
                bk_obj_id=nodes[0]["bk_obj_id"],
                bk_obj_name=nodes[0]["bk_obj_name"]
            ))
        nodes = [child for node in nodes for child in node["child"]]

    return model


def topo_inst_dict(bk_biz_id):
    queue = [copy.deepcopy(topo_tree(bk_biz_id))]
    inst_obj_dict = {}

    while queue:
        node = queue.pop()
        inst_obj_dict["{}|{}".format(node["bk_obj_id"], node["bk_inst_id"])] = node
        if not node.get("topo_link"):
            node["topo_link"] = ["{}|{}".format(node["bk_obj_id"], node["bk_inst_id"])]
            node["topo_link_display"] = [node["bk_inst_name"]]
        for child in node["child"]:
            child["topo_link"] = node["topo_link"] + ["{}|{}".format(child["bk_obj_id"], child["bk_inst_id"])]
            child["topo_link_display"] = node["topo_link_display"] + [child["bk_inst_name"]]

        queue = queue + node["child"]
        del node["child"]
    return inst_obj_dict


# 获取主机所有拓扑信息
def _get_host_topo_inst(bk_biz_id, host_list):
    topo_tree_dict = topo_tree(bk_biz_id)
    if not topo_tree_dict:
        return

    queue = [copy.deepcopy(topo_tree_dict)]
    inst_obj_dict = {}
    topo_link_dict = {}

    while queue:
        node = queue.pop()
        inst_obj_dict["{}|{}".format(node["bk_obj_id"], node["bk_inst_id"])] = node
        if not node.get("topo_link"):
            node["topo_link"] = ["{}|{}".format(node["bk_obj_id"], node["bk_inst_id"])]
            node["topo_link_display"] = [node["bk_inst_name"]]
        topo_link_dict["{}|{}".format(node["bk_obj_id"], node["bk_inst_id"])] = node["topo_link"]
        for child in node["child"]:
            child["topo_link"] = node["topo_link"] + ["{}|{}".format(child["bk_obj_id"], child["bk_inst_id"])]
            child["topo_link_display"] = node["topo_link_display"] + [child["bk_inst_name"]]

        queue = queue + node["child"]
        del node["child"]

    for host in host_list:
        module_list = ["module|%s" % x["bk_module_id"] for x in host["module"]]
        topo_dict = {"module": [], "set": []}
        for module_key in module_list:
            for inst_key in topo_link_dict.get(module_key, []):
                bk_obj_id, _ = inst_key.split("|")
                if bk_obj_id not in topo_dict:
                    topo_dict[bk_obj_id] = []
                if inst_key not in ["{}|{}".format(x["bk_obj_id"], x["bk_inst_id"]) for x in topo_dict[bk_obj_id]]:
                    topo_dict[bk_obj_id].append(inst_obj_dict[inst_key])
        for bk_obj_id in topo_dict:
            host[bk_obj_id] = topo_dict[bk_obj_id]


@using_cache(CacheType.CC, is_cache_func=lambda res: res)
def raw_hosts(cc_biz_id):
    """ Do not use me，Please use `hosts` func"""
    result = client.cc.search_host(bk_biz_id=cc_biz_id, condition=[{"bk_obj_id": "module", "fields": []}])
    data = result.get("data")["info"] if result["result"] else []

    _get_host_topo_inst(cc_biz_id, data)
    # 企业版的业务模块就是分布模块
    for host in data:
        host["app_module"] = host["module"]

    return data


def hosts(cc_biz_id):
    data = raw_hosts(cc_biz_id)
    host_list = Host.create_host_list(data)
    for host in host_list:
        host.bk_biz_id = cc_biz_id
    _code_replace(host_list)
    return host_list


def agent_status(cc_biz_id, host_list):
    """获取agent状态信息
    agent状态详细分成4个状态：正常，离线，未安装。已安装，无数据。
    """
    result = collections.defaultdict(int)
    ip_info_list = list()
    for host in host_list:
        ip_info_list.append({
            "ip": host.bk_host_innerip,
            "plat_id": host.bk_cloud_id[0]["bk_inst_id"]
        })
    if not ip_info_list:
        return {}
    status_list = client.job.get_agent_status(
        app_id=cc_biz_id,
        is_real_time=1,
        ip_infos=ip_info_list
    ).get("data") or {}
    for info in status_list:
        host_id = Host(dict(
            ip=info["ip"],
            bk_cloud_id=info["plat_id"]
        ), cc_biz_id).host_id
        exist = bool(info["status"])
        if not exist:
            result[host_id] = AGENT_STATUS.NOT_EXIST
            continue
        else:
            result[host_id] = AGENT_STATUS.ON

    return result


def hosts_and_status(cc_biz_id, host_list_info=None, agent_dict_info=None):
    host_list = hosts(cc_biz_id)
    hosts_agent_status = agent_status(cc_biz_id, host_list)
    if (host_list_info and agent_dict_info) is not None:
        host_list_info.extend(host_list)
        agent_dict_info.update(hosts_agent_status)
    return host_list, hosts_agent_status


def get_host_and_status(cc_biz_id=None):
    if cc_biz_id:
        biz_ids = [cc_biz_id]
    else:
        biz_ids_result = client.cc.search_business()
        biz_ids = [info['bk_biz_id'] for info in biz_ids_result['data']['info']] if biz_ids_result.get('data') else []

    from bkmonitor.utils.thread_backend import InheritParentThread
    host_list = list()
    agent_dict = dict()
    th_list = [
        InheritParentThread(target=hosts_and_status, args=(i, host_list, agent_dict)) for i in biz_ids
    ]
    list(map(lambda t: t.start(), th_list))
    list(map(lambda t: t.join(), th_list))

    return host_list, agent_dict, biz_ids


def process_port_info(cc_biz_id, host_id_mapping_ip, limit_port_num=None):
    pp_info = {}
    result = search_service_instance_details(cc_biz_id)
    for pp in result:
        host_id = host_id_mapping_ip[pp['bk_host_id']]
        if pp.get("process_instances"):
            from monitor_api.models import ProcessPortIndex
            for item in pp["process_instances"]:
                pp_instance = DictObj({
                    "host_id": host_id,
                    "name": item['process']["bk_process_name"],
                    "protocol": item['process']["protocol"],
                    "ports": ProcessPortIndex.parse_cc_ports(item['process']["port"]),
                    "status": AGENT_STATUS.UNKNOWN
                })
                if limit_port_num:
                    pp_instance.ports = pp_instance.ports[:limit_port_num]
                pp_info.setdefault(host_id, []).append(pp_instance)
    return pp_info


def _code_replace(host_list):
    """地理位置、运营商、系统类型等枚举信息替换"""
    for host in host_list:
        if 'bk_state_name' not in host:
            host_list.remove(host)
            continue
        country_ch_name = host['bk_state_name']
        province_ch_name = ''
        isp_name = host['bk_isp_name']

        for province in CHINESE_PROVINCES:
            if host['bk_province_name'] == province['code']:
                province_ch_name = province['cn']
                break
        for country in COUNTRIES:
            if host['bk_state_name'] == country['code']:
                country_ch_name = country['cn']
                break
        for isp in ISP_LIST:
            if host['bk_isp_name'] == isp['code']:
                isp_name = isp['cn']
                break

        host['bk_province_name'] = province_ch_name
        host['bk_state_name'] = country_ch_name
        host['Region'] = province_ch_name
        host['bk_isp_name'] = isp_name

    return host_list


@using_cache(CacheType.CC)
def topo_tree(bk_biz_id):
    result = client.cc.search_biz_inst_topo(
        bk_biz_id=bk_biz_id,
        level=-1
    ).get("data") or []

    free_set = client.cc.get_biz_internal_module(
        bk_biz_id=bk_biz_id,
        bk_supplier_account=0
    ).get("data") or {}

    if free_set.get("module"):
        free_set = dict(
            bk_obj_id="set",
            bk_obj_name="集群",
            bk_inst_id=free_set["bk_set_id"],
            bk_inst_name=free_set["bk_set_name"],
            child=[dict(
                bk_obj_id="module",
                bk_obj_name="模块",
                bk_inst_id=m["bk_module_id"],
                bk_inst_name=m["bk_module_name"],
                child=[]
            ) for m in free_set["module"]]
        )

    if result:
        result = result[0]
        if free_set:
            result["child"] = [free_set] + result["child"]
        return result


def host_property_list(cc_biz_id):
    try:
        result = client.cc.search_object_attribute(
            bk_obj_id="host"
        )
    except Exception as _:
        return []
    return result.get("data", [])


def get_all_role_names(cc_biz_id, role_list=None, show_details=False):
    """
    获取运维、运营规划、产品、DBA、产品人员、开发人员、运营质量管理人员列表
    :param cc_biz_id: 业务id
    :param role_list: 角色列表['ProductPm', 'AppDevMan']
                        default:
                            ["Maintainers", 'OperationPlanning',
                            'PmpProductMan', 'PmpDBAMajor', 'PmpQC',
                            'ProductPm', 'AppDevMan']
    :return: {name:name...}
    """
    # Build role_list if not given
    if not role_list:
        role_list = get_configuration_role_list(False)
    biz = resource.biz.get_app_by_id(cc_biz_id)
    role_info = biz.get_user_dict_by_roles(role_list, show_details)
    return role_info


def get_configuration_role_list(is_all):
    """
    获取配置人员
    :param is_all: 是否获取全部配置人员，如果为false,则把Operator和
                    BakOperator这两个角色去掉
    :return:
        ["Maintainers", 'OperationPlanning',
        'PmpProductMan', 'PmpDBAMajor', 'PmpQC',
        'ProductPm', 'AppDevMan']
    """
    if is_all:
        return list(settings.NOTIRY_MAN_DICT.keys())
    else:
        notice_man = settings.NOTIRY_MAN_DICT.copy()
        del notice_man['Operator']
        del notice_man['BakOperator']
        return sorted(notice_man.keys())


def app_notice_user(cc_biz_id):
    """
    获取指定业务下通知角色人员信息
    """
    biz = resource.biz.get_app_by_id(cc_biz_id)
    data = biz.select_fields(get_configuration_role_list(True))
    return data


def app_auth_user(cc_biz_id):
    """
    获取指定业务下有权限人员信息
    """
    biz = resource.biz.get_app_by_id(cc_biz_id)
    data = biz.select_fields(settings.OLD_AUTHORIZED_ROLES)
    return data


def plat_id_gse_to_cc(plat_id):
    """
    （deprecated）将gse的plat_id转换成cc的plat_id
    """
    return plat_id


def plat_id_cc_to_gse(plat_id):
    """
    （deprecated）将cc的plat_id转换成gse的plat_id
    """
    return plat_id


def plat_id_cc_to_job(plat_id):
    """
    将cc的plat_id转换成job的plat_id
    """
    return plat_id


def plat_id_job_to_cc(plat_id):
    """
    将job的plat_id转换成cc的plat_id
    """
    return plat_id


@using_cache(CacheType.HOST)
def _host_detail(ip, bk_cloud_id, bk_biz_id):
    if isinstance(bk_cloud_id, list):
        bk_cloud_id = bk_cloud_id[0]["bk_inst_id"]

    condition = [
        {
            "bk_obj_id": "module",
            "fields": []
        },
        {
            "bk_obj_id": "host",
            "condition": [
                {
                    "field": "bk_host_innerip",
                    "operator": "$eq",
                    "value": ip
                },
                {
                    "field": "bk_cloud_id",
                    "operator": "$eq",
                    "value": bk_cloud_id
                }
            ]
        }
    ]

    result = client.cc.search_host(bk_biz_id=bk_biz_id, condition=condition)

    if not result['result']:
        raise CustomException("查询主机失败: %s" % result['message'])

    _get_host_topo_inst(bk_biz_id, result["data"]["info"])

    for host in result["data"]["info"]:
        host["cc_app_module"] = [x["bk_inst_id"] for x in host["module"]]
        host["cc_topo_set"] = [x["bk_inst_id"] for x in host["set"]]

    if result['data']['info']:
        return result['data']['info']


def host_detail(ip, bk_cloud_id, bk_biz_id):
    host_objects = hosts(bk_biz_id)
    for host in host_objects:
        if host.bk_host_innerip == ip and host.bk_cloud_id[0]['bk_inst_id'] == bk_cloud_id:
            host["cc_app_module"] = [x["bk_inst_id"] for x in host["module"]]
            host["cc_topo_set"] = [x["bk_inst_id"] for x in host["set"]]
            return host


@using_cache(CacheType.BIZ, user_related=False)
def get_blueking_biz_id():
    """
    获取蓝鲸业务所属的业务ID
    """
    result = client.cc.search_business(
        fields=[
            "bk_biz_id",
            "bk_biz_name"
        ],
        condition={
            "bk_biz_name": "蓝鲸"
        }
    )
    if not result['result'] or not result['data']['info']:
        raise CustomException("查询蓝鲸业务ID失败: %s" % result['message'])
    biz_id = result['data']['info'][0]['bk_biz_id']
    return biz_id


def get_monitor_biz_id():
    """
    获取蓝鲸监控所属业务ID
    """
    return get_blueking_biz_id()


def get_bkdata_biz_id():
    """
    获取数据平台业务ID
    """
    return get_blueking_biz_id()


@using_cache(CacheType.CC)
def _get_hosts_by_inst_id(bk_biz_id, bk_obj_id, bk_inst_id):
    condition = [
        {
            "bk_obj_id": bk_obj_id if bk_obj_id in ["module", "set", "biz"] else "object",
            "fields": [],
            "condition": [
                {
                    "field": "bk_%s_id" % bk_obj_id if bk_obj_id in ["module", "set", "biz"] else "bk_inst_id",
                    "operator": "$in" if isinstance(bk_inst_id, list) else "$eq",
                    "value": bk_inst_id
                }
            ]
        }
    ]

    if bk_obj_id != "module":
        condition.append({
            "bk_obj_id": "module",
            "fields": [],
        })

    if bk_obj_id != "set":
        condition.append({
            "bk_obj_id": "set",
            "fields": [],
        })

    result = client.cc.search_host(bk_biz_id=bk_biz_id, condition=condition)

    if not result["result"]:
        raise CustomException("查询主机失败: %s" % result['message'])

    _get_host_topo_inst(bk_biz_id, result['data']['info'])

    for host in result["data"]["info"]:
        host["cc_app_module"] = [x["bk_inst_id"] for x in host["module"]]
        host["cc_topo_set"] = [x["bk_inst_id"] for x in host["set"]]

    return result["data"]["info"]


def get_hosts_by_inst_id(bk_biz_id, bk_obj_id, bk_inst_id):
    return Host.create_host_list(_get_hosts_by_inst_id(bk_biz_id, bk_obj_id, bk_inst_id))


# TODO: 以下函数内部版逻辑需要用到，接口暂时不做改动
@using_cache(CacheType.CC)
def set_name(cc_biz_id, set_id_list):
    if not hasattr(set_id_list, "__iter__"):
        set_id_list = [set_id_list]
    set_list = client.cc.search_set(
        bk_biz_id=cc_biz_id,
        fields=['bk_set_name', 'bk_set_id']
    ).get("data")['info'] or []
    # set_id转为字符串，保持与旧接口一致
    for item in set_list:
        item['bk_set_id'] = str(item['bk_set_id'])
    set_name_dict = dict().fromkeys(set_id_list, _("未知"))
    for set_item in set_list:
        if set_item["bk_set_id"] in set_name_dict:
            set_name_dict[set_item["bk_set_id"]] = set_item["bk_set_name"]
    return set_name_dict


@using_cache(CacheType.CC)
def module_name(cc_biz_id, module_id_list):
    if not hasattr(module_id_list, "__iter__"):
        module_id_list = [module_id_list]
    module_list = client.cc.get_modules(app_id=cc_biz_id).get("data") or []
    module_name_dict = dict().fromkeys(module_id_list, _("未知"))
    for module_item in module_list:
        if "ModuleID" not in module_item:
            continue
        module_id = module_item["ModuleID"]
        if module_id in module_name_dict:
            module_name_dict[module_id] = module_item["ModuleName"]
    return module_name_dict


@using_cache(CacheType.CC)
def sets(cc_biz_id):
    """获取业务下SET列表，按机器数量排序"""
    # 获取set列表
    with ignored(Exception):
        set_list = client.cc.search_set(
            bk_biz_id=cc_biz_id,
            fields=['bk_set_name', 'bk_set_id']
        ).get("data")['info'] or []
        # set_id转为字符串，保持与旧接口一致
        set_id_list = [str(set_item["bk_set_id"]) for set_item in set_list]
        host_list = hosts(cc_biz_id)
        if set_id_list:
            set_info = collections.defaultdict(set)
            for host in host_list:
                if host["SetID"] in set_id_list:
                    set_info[host["SetID"]].add(host_key(host))
                    set_info["0"].add(host_key(host))
            for set_item in set_list:
                set_item["host_count"] = len(set_info[str(set_item["bk_set_id"])])
                set_item["SetName"] += ' [%s]' % set_item["host_count"]
            set_list = sorted(
                set_list, key=lambda x: x['host_count'], reverse=True
            )
            return set_list, len(set_info["0"])
    return [], 0


@using_cache(CacheType.CC)
def modules(cc_biz_id, set_id_list=None):
    """获取业务下的模块列表，按机器数量排序"""
    with ignored(Exception):
        if set_id_list and (not hasattr(set_id_list, "__iter__")):
            set_id_list = [set_id_list]
        if set_id_list is not None:
            set_id_list = ";".join(map(str, set_id_list))
        if set_id_list and set_id_list != '0':
            module_list = client.cc.get_modules_by_property(
                app_id=cc_biz_id, set_id=set_id_list
            ).get("data") or []
        else:
            module_list = client.cc.get_modules_by_property(
                app_id=cc_biz_id).get("data") or []
        module_id_list = [module_item["ModuleID"]
                          for module_item in module_list]
        host_list = hosts(cc_biz_id)
        if module_id_list:
            module_info = collections.defaultdict(set)
            for host in host_list:
                if host["ModuleID"] in module_id_list:
                    module_info[host["ModuleID"]].add(host_key(host))
                    module_info["0"].add(host_key(host))
            for set_item in module_list:
                set_item["host_count"] = len(
                    module_info[set_item["ModuleID"]]
                )
                set_item["host_list"] = module_info[set_item["ModuleID"]]
                set_item["ModuleName"] += ' [%s]' % set_item["host_count"]
                set_item["TopoSetID"] = set_item["SetID"]
            module_list = sorted(
                module_list, key=lambda x: x['host_count'], reverse=True)
            return module_list, len(module_info["0"])
    return [], 0


def topo_modules(cc_biz_id, set_id_list=None):
    """获取业务下的分布模块列表，按机器数量排序"""
    return modules(cc_biz_id, set_id_list)


def get_proc_instance(bk_biz_id, module_id):
    params = {
        'metadata': {
            'bk_biz_id': bk_biz_id,
        },
        'module_id': module_id,
    }
    result = client.cc.get_proc_sercvices_instance(params)
    if result['result']:
        return result['data']['info']
    else:
        return []


def get_host_list_by_ip_list(ip_list, bk_biz_ids):
    ip = {
        'data': [host['ip'] for host in ip_list],
        'exact': 1,
        'flag': 'bk_host_innerip'
    }
    condition = [
        {
            'bk_obj_id': 'biz',
            'fields': [],
            'condition': [
                {
                    'field': 'bk_biz_id',
                    'operator': '$in',
                    'value': bk_biz_ids
                }
            ]
        }
    ]
    cc_result = client.cc.search_host({'ip': ip, 'condition': condition})
    return cc_result['data']['info'] if cc_result['result'] else []


def search_module(bk_biz_id, bk_set_id):
    result = client.cc.search_module(bk_biz_id=bk_biz_id, bk_set_id=bk_set_id)
    return result['data']['info'] if result['result'] else []


def search_insts(bk_obj_id, bk_inst_ids):
    if not isinstance(bk_inst_ids, list):
        bk_inst_ids = [bk_inst_ids]

    params = {
        'bk_obj_id': bk_obj_id,
        'bk_supplier_account': "0",
        'condition': {
            bk_obj_id: [
                {
                    'field': "bk_%s_id" % bk_obj_id if bk_obj_id in ["module", "set", "biz"] else "bk_inst_id",
                    'operator': '$in',
                    'value': bk_inst_ids
                }
            ]
        }
    }
    result = client.cc.search_inst(params)
    if not result["result"]:
        return []

    return result["data"]["info"]


def search_inst(bk_obj_id, bk_inst_id):
    """
    获取CMDB的实例信息
    """
    params = {
        'bk_obj_id': bk_obj_id,
        'bk_supplier_account': "0",
        'condition': {
            bk_obj_id: [
                {
                    'field': "bk_%s_id" % bk_obj_id if bk_obj_id in ["module", "set", "biz"] else "bk_inst_id",
                    'operator': '$eq',
                    'value': bk_inst_id
                }
            ]
        }
    }
    result = client.cc.search_inst(params)
    if not result["result"] or not result['data']['info']:
        raise CustomException("查询实例信息失败: %s" % result['message'])

    return result["data"]["info"][0]


def search_obj(bk_obj_id):
    """
    获取CMDB的对象信息
    """
    params = {
        "bk_obj_id": bk_obj_id,
        "bk_supplier_account": "0"
    }
    result = client.cc.search_objects(params)
    if not result["result"] or not result['data']:
        raise CustomException("查询对象信息失败: %s" % result['message'])

    return result["data"][0]


def search_service_category(bk_biz_id):
    """
    获取服务分类(临时)
    """
    import requests
    import json
    url = 'https://cmdbee-dev.bktencent.com/api/v3/findmany/proc/service_category'
    params = {
        "metadata": {
            "label": {
                "bk_biz_id": str(bk_biz_id)
            }
        }
    }
    from bkmonitor.middlewares.request_middlewares import get_request
    cookie_dict = (getattr(get_request(), 'COOKIES', None))
    cookie = ''
    for key, value in cookie_dict.items():
        cookie += "{key}={value};".format(key=key, value=value)
    result = requests.post(url=url, data=json.dumps(params), headers={'Cookie': cookie}, verify=False)
    content = json.loads(result.content)
    if not content.get('result'):
        raise CustomException("查询CMDB服务分类失败: %s" % content.get('bk_error_msg'))

    return content['data']['info']


def search_service_instance(bk_biz_id, bk_module_id=None):
    """
    根据模块获取服务实例(临时)
    """
    import requests
    import json
    url = 'https://cmdbee-dev.bktencent.com/api/v3/findmany/proc/service_instance'
    params = {
        "metadata": {
            "label": {
                "bk_biz_id": str(bk_biz_id)
            }
        }
    }
    if bk_module_id:
        params["bk_module_id"] = bk_module_id

    from bkmonitor.middlewares.request_middlewares import get_request
    cookie_dict = (getattr(get_request(), 'COOKIES', None))
    cookie = ''
    for key, value in cookie_dict.items():
        cookie += "{key}={value};".format(key=key, value=value)
    result = requests.post(url=url, data=json.dumps(params), headers={'Cookie': cookie}, verify=False)
    content = json.loads(result.content)
    if not content["result"]:
        raise CustomException("查询CMDB服务实例失败: %s" % content['bk_error_msg'])

    return content['data']['info']


def search_service_instance_details(bk_biz_id, service_instance_ids=None):
    """
    根据模块获取服务实例详情(临时)
    """
    import requests
    import json
    url = 'https://cmdbee-dev.bktencent.com/api/v3/findmany/proc/service_instance/details'
    params = {
        "metadata": {
            "label": {
                "bk_biz_id": str(bk_biz_id)
            }
        }
    }
    if service_instance_ids:
        params["service_instance_ids"] = service_instance_ids

    from bkmonitor.middlewares.request_middlewares import get_request
    cookie_dict = (getattr(get_request(), 'COOKIES', None))
    cookie = ''
    for key, value in cookie_dict.items():
        cookie += "{key}={value};".format(key=key, value=value)
    result = requests.post(url=url, data=json.dumps(params), headers={'Cookie': cookie}, verify=False)
    if result.status_code != 200:
        logger.error(
            _("获取业务下进程端口信息失败：[cc_biz_id: %s]") % bk_biz_id)
        return {}
    return json.loads(result.content)['data']['info']
