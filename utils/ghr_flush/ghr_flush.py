# #!/home/md043797/anaconda3/bin/python
from subprocess import Popen, PIPE, STDOUT
from statistics import mean, pstdev, stdev


base_cmd = "make clean; make all;"
sum_list = []
avg_list = []
pstdev_list = []
stdev_list = []
min_list = []
max_list = []

for k in range(100):
    error_list = []
    op = Popen(base_cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    stdout, nothing = op.communicate()

    for x in range(200):
        cmd = f"taskset 0x8 ./ghr_flush_test"
        final = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
        stdout, nothing = final.communicate()
        stdout = int(stdout.decode("utf-8").splitlines()[-1].split(' ')[1])
        error_list.append(stdout)

    with open("ghr_flush_test.c", "r") as f:
        lines = f.readlines()
    new_lines = []
    for line in lines:
        line_str = f"AT_START;"
        line_str_1 = f"AT_START;AT;"
        if line_str in line:
            line = line.replace(line_str, line_str_1)
        new_lines.append(line)
    with open("ghr_flush_test.c", "w+") as f:
        for line in new_lines:
            f.write(line)

    print(f"b_{k+1} = {error_list}")

    sum_list.append(sum(error_list))
    pstdev_list.append(pstdev(error_list))
    stdev_list.append(stdev(error_list))
    avg_list.append(mean(error_list))
    min_list.append(min(error_list))
    max_list.append(max(error_list))

print(f"sum_list = {sum_list}")
print(f"pstdev_list = {pstdev_list}")
print(f"stdev_list = {stdev_list}")
print(f"avg_list = {avg_list}")
print(f"min_list = {min_list}")
print(f"max_list = {max_list}")
