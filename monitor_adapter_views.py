return render(
    request, 'service-worker.html', {
        'cc_biz_id': cc_biz_id,
        'AGENT_SETUP_URL': settings.AGENT_SETUP_URL,
        'SUN': 'sunzhiyu'
    }
)
return render(
    request, 'index.html', {
        'cc_biz_id': cc_biz_id,
        'AGENT_SETUP_URL': settings.AGENT_SETUP_URL,
        'SUN': 'sunzhiyu'
    }
)

def service_worker(request):
    # with open(os.path.join(settings.BASE_DIR, 'static/monitor/service-worker.js'), 'r') as f:
    #     content = f.read()
    # content = get_template(os.path.join(settings.BASE_DIR, 'static/monitor/service-worker.js'))
    # response = HttpResponse(content.render({'sun': 'sunzhiyu'}), content_type='application/javascript')
    return render(
        request, 'service-worker.js', content_type='application/javascript'
    )

def todict(obj):
    if hasattr(obj, "__iter__"):
        return [todict(v) for v in obj]
    elif hasattr(obj, "__dict__"):
        return dict([(key, todict(value))
            for key, value in obj.__dict__.items()
            if not callable(value) and not key.startswith('_')])
    else:
        return obj

def to_dict(obj):
    if isinstance(obj, dict):
        data = {}
        for (k, v) in obj.items():
            data[k] = to_dict(v)
        return data
    elif hasattr(obj, "__iter__") and not isinstance(obj, str):
        return [to_dict(v) for v in obj]
    elif hasattr(obj, "__dict__"):
        data = dict([(key, to_dict(value))
                     for key, value in obj.__dict__.items()
                     if not callable(value) and not key.startswith('_')])
        return data
    else:
        return obj