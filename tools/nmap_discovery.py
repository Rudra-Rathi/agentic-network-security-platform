import subprocess


def icmp_discovery(target):
    cmd = ["nmap", "-sn", target]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout


def tcp_discovery(target):
    cmd = ["nmap", "-sS", "-p", "80,443,22", target]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout