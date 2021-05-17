#!/home/md043797/anaconda3/bin/python
from subprocess import Popen, PIPE, STDOUT
from statistics import mean, pstdev, stdev


base_cmd = "make clean; make all;"
sum_list = []
avg_list = []
pstdev_list = []
stdev_list = []

for k in range(50):
    error_list = []
    op = Popen(base_cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    stdout, nothing = op.communicate()

    for x in range(100):
        cmd = f"taskset 0x8 ./history_based_activator"
        final = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
        stdout, nothing = final.communicate()
        stdout = int(stdout.decode("utf-8").splitlines()[-1].split(' ')[1])
        error_list.append(stdout)

    with open("history_based_activator.c", "r") as f:
        lines = f.readlines()
    new_lines = []
    for line in lines:
        line_str = f"if ((i>{k})"
        line_str_1 = f"if ((i>{k+1})"
        if line_str in line:
            line = line.replace(line_str, line_str_1)
            print(line)
        new_lines.append(line)
    with open("history_based_activator.c", "w+") as f:
        for line in new_lines:
            f.write(line)
    print(f"b_{k+1} = {error_list}")

    sum_list.append(sum(error_list))
    pstdev_list.append(pstdev(error_list))
    stdev_list.append(stdev(error_list))
    avg_list.append(mean(error_list))

print(f"sum_list = {sum_list}")
print(f"pstdev_list = {pstdev_list}")
print(f"stdev_list = {stdev_list}")
print(f"avg_list = {avg_list}")