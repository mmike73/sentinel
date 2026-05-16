import subprocess

proc = subprocess.Popen(
    ['dmesg', '--follow', '--since', '1 min ago'],
    stdout=subprocess.PIPE,
    text=True
)

for line in iter(proc.stdout.readline, ''):
    print(line, end='')
