# MNScan
masscan+nmap，结合了massacn的快速扫描和nmap精准识别端口的特点，自动识别http/https端口生成URL。
# python3编写
# 如果你的masscan和nmap如果在环境变量里，请直接跳过这一条，不在环境变量里的话需要按下面操作配置一下
这两个地方需要手动配置下：

#masscan

    masscan_path = "/usr/local/bin/masscan"  # 替换为自己的 masscan 路径，再将下面的"masscan"替换为masscan_path
    
    # 根据输入参数类型构建 masscan 命令
    if is_valid_ip(target):
        masscan_cmd = ["masscan", target, "--ports", ports, "-oJ", output_file_path, "--rate", rate]
    else:
        masscan_cmd = ["masscan", "-iL", target, "--ports", ports, "-oJ", output_file_path, "--rate", rate]
#nmap


    nmap_path = "/usr/local/bin/nmap"    # 替换为自己的 nmap 路径，再将下面的"nmap"替换为nmap_path
    ports_str = ",".join(ports)
    nmap_cmd = ["nmap", ip, "-p", ports_str, "-sV", "-Pn", "-oN", output_file_path,"--append-output"]

# 使用方法
python MNScan.py -h
    
    usage: MNScan.py [-h] [-i TARGET] [-f TARGET] [-o OUTPUT_FILE_PATH] [-r RATE]
                 [-p PORTS]
                 
    Run Masscan with custom parameters

    optional arguments:
  
    -h, --help            show this help message and exit
  
    -i TARGET, --ip TARGET
                        Single target IP address
  
    -f TARGET, --file TARGET
                        File containing target IPs (one per line)
  
    -o OUTPUT_FILE_PATH, --output OUTPUT_FILE_PATH
                        Output file path,default output.txt
  
    -r RATE, --rate RATE  Scan rate,dafault 1000
  
    -p PORTS, --ports PORTS
                        Port range (default: 1-65535)
# 使用示例
                        
python MNScan.py -i 192.168.1.1  #直接输入ip，支持格式192.168.1.1,192.168.2.1/24,192.168.1.1-192.168.1.255

python MNScan.py -f ip.txt  #扫描ip文件，每行为一个ip对象

python MNScan.py -i 192.168.1.1 -o out.txt  #指定输出文件，默认输出为output.txt，输出masscan的json形式结果和nmap全部结果

python MNScan.py -i 192.168.1.1 -r 1000  #指定masscan扫描速率，默认为1000，速率设置太高可能导致masscan扫描结果不全

python MNScan.py -i 192.168.1.1 -p 1000  #指定扫描端口，默认为1-65535

#  输出结果
端口识别

<img width="546" alt="图片" src="https://github.com/Catchf1r3/MNScan/assets/110521424/4f0ffff5-1af6-4efb-b5ba-6b66381f9096">

http/https提取

<img width="232" alt="图片" src="https://github.com/Catchf1r3/MNScan/assets/110521424/076baf2d-f230-485d-8a9f-56838ac72bc4">
