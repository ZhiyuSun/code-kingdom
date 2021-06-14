try:
    result = resource.node_man.subscription_host_status(
        subscription_id_list=[config.deployment_config.subscription_id for config in config_data_list])
except BKAPIError as e:
    logger.error('请求节点管理主机运行状态接口失败: {}'.format(e))
    return

# 统计节点管理订阅的正常数、异常数、是否有任务在运行
for item in result:
    is_deploying = item['is_running']
    total_instance_count = len(item['instances'])
    error_instance_count = [host_status['status']
                            for host_status in item['instances']].count(CollectStatus.FAILED)

    self.realtime_data.update({item['subscription_id']: {
        'error_instance_count': error_instance_count,
        'total_instance_count': total_instance_count,
        'is_deploying': is_deploying
    }})