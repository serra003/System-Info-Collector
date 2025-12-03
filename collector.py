import platform
import psutil
import os
import datetime
import json
import time

def get_system_info():
    return {
        'System': platform.system(),
        'Node Name': platform.node(),
        'Release': platform.release(),
        'Version': platform.version(),
        'Machine': platform.machine(),
        'Processor': platform.processor()
    }

def get_running_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes

def detect_suspicious(processes):
    known_processes = ['System', 'svchost.exe', 'chrome.exe', 'Code.exe', 'explorer.exe']
    suspicious = []
    for proc in processes:
        name = proc['name']
        user = proc['username']
        if user is None or (name not in known_processes):
            suspicious.append(proc)
    return suspicious

def compare_snapshots(old_processes, new_processes):
    old_pids = {proc['pid'] for proc in old_processes}
    new_pids = {proc['pid'] for proc in new_processes}

    started = [proc for proc in new_processes if proc['pid'] not in old_pids]
    stopped = [proc for proc in old_processes if proc['pid'] not in new_pids]

    return started, stopped

def get_network_connections():
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        connections.append({
            'pid': conn.pid,
            'laddr': f"{conn.laddr.ip}:{conn.laddr.port}",
            'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
            'status': conn.status
        })
    return connections

def save_to_json(system_info, processes, suspicious, started, stopped, connections):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"system_log_{timestamp}.json"
    filepath = os.path.join(os.getcwd(), filename)

    data = {
        "system_info": system_info,
        "processes": processes,
        "suspicious_processes": suspicious,
        "started_processes": started,
        "stopped_processes": stopped,
        "network_connections": connections
    }

    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

    print(f"JSON log saved to: {filepath}")


previous_processes = []

while True:
    system_info = get_system_info()
    processes = get_running_processes()
    suspicious = detect_suspicious(processes)
    started, stopped = compare_snapshots(previous_processes, processes) if previous_processes else ([], [])
    connections = get_network_connections()

    save_to_json(system_info, processes, suspicious, started, stopped, connections)

    previous_processes = processes

    time.sleep(60)
