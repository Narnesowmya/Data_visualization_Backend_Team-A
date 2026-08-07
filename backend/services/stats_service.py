from database.mongo import events_collection, assets_collection, vulnerabilities_collection, threats_collection


async def get_dashboard_stats():
    total_events = await events_collection.count_documents({})
    critical_alerts = await events_collection.count_documents({"severity": "critical"})
    open_events = await events_collection.count_documents({"status": "open"})
    resolved_events = await events_collection.count_documents({"status": "resolved"})

    total_assets = await assets_collection.count_documents({})

    total_vulnerabilities = await vulnerabilities_collection.count_documents({})
    critical_vulnerabilities = await vulnerabilities_collection.count_documents({"severity": "critical"})

    active_threats = await threats_collection.count_documents({"status": "active"})

    return {
        "total_events": total_events,
        "critical_alerts": critical_alerts,
        "open_events": open_events,
        "resolved_events": resolved_events,
        "total_assets": total_assets,
        "total_vulnerabilities": total_vulnerabilities,
        "critical_vulnerabilities": critical_vulnerabilities,
        "active_threats": active_threats,
    }
