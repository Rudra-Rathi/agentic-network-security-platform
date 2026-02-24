import subprocess

def icmp_discovery(target):
    cmd = ["nmap", "-sn", target]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout