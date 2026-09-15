from agent.sensors.process_display import build_process_inventory, friendly_process_name


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)
    print(f"PASS | {msg}")


def main():
    check(friendly_process_name({"name":"chrome.exe","exe":r"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"}) == "Google Chrome", "Chrome is shown as Google Chrome")
    check(friendly_process_name({"name":"python.exe","exe":r"C:\\Python314\\python.exe"}) == "Python", "python.exe is shown as Python")
    check(friendly_process_name({"name":"WINWORD.EXE","exe":r"C:\\Program Files\\Microsoft Office\\WINWORD.EXE"}) == "Microsoft Word", "Word technical executable is humanized")
    check(friendly_process_name({"name":"custom_worker.exe","exe":None}) == "Custom Worker", "unknown executable uses bounded humanized fallback")

    snap={"processes":[
        {"pid":10,"name":"chrome.exe","exe":r"C:\\Chrome\\chrome.exe","username":"U","cpu_percent":1.0,"memory_percent":2.5},
        {"pid":11,"name":"chrome.exe","exe":r"C:\\Chrome\\chrome.exe","username":"U","cpu_percent":2.0,"memory_percent":1.5},
        {"pid":20,"name":"python.exe","exe":r"C:\\Python\\python.exe","username":"U","cpu_percent":0.5,"memory_percent":1.0},
    ]}
    rows=build_process_inventory(snap,limit=18)
    check(len(rows)==2,"same application processes are aggregated")
    check(rows[0]["display_name"]=="Google Chrome","largest aggregate is first")
    check(rows[0]["processes"]==2,"aggregate process count is exact")
    check(rows[0]["memory_percent"]==4.0,"aggregate memory percent is exact")
    check(rows[0]["pids"]==[10,11],"bounded PID samples remain visible")
    check("technical_name" in rows[0],"technical process name remains preserved")
    print("RESULT: PASS")

if __name__ == "__main__":
    main()
