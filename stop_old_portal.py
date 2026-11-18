#!/usr/bin/env python3
"""Stop only Python processes running monitor_portal.py from this installation."""
import os, pathlib, signal, subprocess, sys, time
app = pathlib.Path(sys.argv[1]).resolve()
me=os.getpid()
found=set()
for proc in pathlib.Path('/proc').glob('[0-9]*'):
    try:
        pid=int(proc.name)
        if pid==me:continue
        args=(proc/'cmdline').read_bytes().split(b'\0')
        args=[a.decode('utf-8','replace') for a in args if a]
        if not args or 'python' not in pathlib.Path(args[0]).name.lower():continue
        if not any(pathlib.Path(a).name=='monitor_portal.py' for a in args[1:]):continue
        try:
            cwd=pathlib.Path(os.readlink(proc/'cwd')).resolve()
            if cwd!=app:continue
        except OSError:
            # The exact script path is sufficient when cwd is unavailable.
            if not any(a==str(app/'monitor_portal.py') for a in args[1:]):continue
        found.add(pid)
    except (OSError,ValueError,PermissionError):pass
if not found:
    try:
        ps=subprocess.run(['ps','-A','-o','PID,ARGS'],capture_output=True,text=True,timeout=4)
        for line in ps.stdout.splitlines()[1:]:
            fields=line.strip().split(None,1)
            if len(fields)<2:continue
            pid=int(fields[0]);cmd=fields[1]
            if pid!=me and 'python' in cmd.split()[0].lower() and 'monitor_portal.py' in cmd:
                found.add(pid)
    except (OSError,ValueError,subprocess.TimeoutExpired):pass
for pid in sorted(found):
    try:os.kill(pid,signal.SIGTERM);print('Stopped older monitor portal process:',pid)
    except (ProcessLookupError,PermissionError) as e:print('Could not stop process:',pid,str(e))
if found:time.sleep(1)
