def get_target_data(config):
    if config.target_object_type == TargetObjectType.SERVICE:
        instance_list = []
        for node in config.deployment_config.target_nodes:
            services = resource.commons.get_services_by_inst_id(
                bk_obj_id=node['bk_obj_id'], bk_inst_id=node['bk_inst_id'], bk_biz_id=config.bk_biz_id)
            for service in services:
                service_id = service['id']
                if service_id not in instance_list:
                    instance_list.append(service_id)
        target_data[config.deployment_config.subscription_id] = {
            'target_object_type': config.target_object_type, 'instance_list': instance_list}

    elif config.deployment_config.target_node_type == TargetNodeType.TOPO:
        instance_list = []
        for node in config.deployment_config.target_nodes:
            hosts = resource.cc.get_hosts_by_inst_id(config.bk_biz_id, node['bk_obj_id'],
                                                     node['bk_inst_id'])
            for host in hosts:
                host_id = host.host_id
                if host_id not in instance_list:
                    instance_list.append(host_id)
        target_data[config.deployment_config.subscription_id] = {
            'target_object_type': config.target_object_type, 'instance_list': instance_list}


th_list = [
    InheritParentThread(target=get_target_data, args=(config,)) for config in config_data_list
]

list(map(lambda t: t.start(), th_list))
list(map(lambda t: t.join(), th_list))
print(target_data)

def handle_nodeman_data(item):
    is_deploying = item['is_running']
    target_sub_data = target_data.get(item['subscription_id'])
    if target_sub_data:
        total_instance_count = 0
        error_instance_count = 0
        for instance in item['instances']:
            if target_sub_data['target_object_type'] == TargetObjectType.HOST:
                host_id = "{}|{}".format(instance['instance_info']['host']['bk_host_innerip'],
                                         instance['instance_info']['host']['bk_cloud_id'][0]['id'])
                if host_id in target_sub_data['instance_list']:
                    total_instance_count += 1
                    if instance['status'] == CollectStatus.FAILED:
                        error_instance_count += 1
            else:
                service_instance_id = instance['instance_info']['service']['id']
                if service_instance_id in target_sub_data['instance_list']:
                    total_instance_count += 1
                    if instance['status'] == CollectStatus.FAILED:
                        error_instance_count += 1
    else:
        total_instance_count = len(item['instances'])
        error_instance_count = [instance['status']
                                for instance in item['instances']].count(CollectStatus.FAILED)

    self.realtime_data.update({item['subscription_id']: {
        'error_instance_count': error_instance_count,
        'total_instance_count': total_instance_count,
        'is_deploying': is_deploying
    }})


th_list = [
    InheritParentThread(target=handle_nodeman_data, args=(item,)) for item in result
]

list(map(lambda t: t.start(), th_list))
list(map(lambda t: t.join(), th_list))

{
    'config_info': {
        'name': 'xxx',
        'version': 'xxx',
        'allow_rollback': True,
        'operation': 'EIDT/AUTO_DEPLOYING/START/STOP',
        'operation_name': 'EIDT/AUTO_DEPLOYING/START/STOP'
    },
    'contents': [
        {
            'label': 'add/remove/update/retry',
            'mode': '',
            "name": "作业平台",
            "path": "业务/集群/作业平台",
            "child": [
                {"bk_service_id": 1,
                 "status": "Failed"}
            ]
        },
        {
            'label': 'start/stop/upgrade',
            'type': 'single',
            "name": "主机",
            "path": "主机",
            "child": [
                {"ip": "x.x.x.x",
                 "status": "SUCCESS"}
            ]
        }
    ]
}

1 版本，要看一下升级是怎么做的
2 数字联动，有
3 无蓝条
4 自动执行，重试需要返回step的内容



主动出发的时候，把订阅关闭

自动执行分支要拆开

采集下发接口，无法判断，是去拿任务状态还是拿自动执行的状态。要么多调一次节点管理接口，要么由前端告诉我们。
我倾向于前端根据列表页判断，从而加一个参数

新增，一个主机分属于两个结点的情况，统计计数
一个采集配置下，主机ip是不一样的吗
前端渲染方式，改成了我们所看到的东西，会不会抖一下，不清楚实现方式
新增 install
删除 uninstall
变更 push config
重试 install uninstall push config

散装
新增，遍历节点，依次把主机放到节点里
启用，同上
停用，同上
升级，同上 update
增删，add remove unchamged如果有，则加到重试里
编辑 add remove updated unchanged如果有，则显示在重试里

主拓
编辑 add remove updated unchanged如果有，则显示在重试里

回滚，相反

服拓


回滚，页面上的操作要不要改

'is_modified': True,
'added':        新增
'updated':      变更
'removed':      删除
'unchanged':    重试


            add        remove               update          unchanged
add         add,add     add                 add,update      add,unchanged
remove                  remove,remove       update          unchanged
update                                      update,update   X
unchanged                                                   unchanged,unchanged


def handle_host_instance_data(self):
    host_instance_data = super(CollectTargetStatusResource, self).handle_host_instance_data()
    data = {
        'config_info': self.get_config_info(),
        'contents': {
            'is_label': False,
            'label_name': '',
            'instances': [{'bk_inst_name': '主机', 'node_path': '主机', 'child': host_instance_data}]
        }
    }
    return data


def handle_host_topo_data(self):
    node_list = self._handle_host_topo_data()
    data = {
        'config_info': self.get_config_info(),
        'contents': {
            'is_label': False,
            'label_name': '',
            'instances': node_list
        }
    }

    return data


def handle_service_topo_data(self):
    node_list = super(CollectTargetStatusResource, self).handle_service_topo_data()
    data = {
        'config_info': self.get_config_info(),
        'contents': {
            'is_label': False,
            'label_name': '',
            'instances': node_list
        }
    }
    return data