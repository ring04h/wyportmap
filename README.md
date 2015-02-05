# wyportmap
目标端口扫描+系统服务指纹识别

运行流程
-----------------------------------
* 为wyportmap指定扫描目标
* 调用nmap启动后台扫描任务
* NmapParser处理扫描结果
* 后台插件自动分析扫描结果，存入数据库（ORM架构，自动创建表和表结构）

BUG反馈
-----------------------------------
> 微博：http://weibo.com/ringzero<br />
> 邮箱：ringzero@0x557.org<br />

使用说明
-----------------------------------
### 配置扫描结果存入的数据库
    使用的ORM架构，会自动创建数据库表和数据结构
    
    修改wyportmap.py文件第18行
    global_dbcoon = 'mysql+mysqldb://root:123456@127.0.0.1:3306/wyportmap'
    global_dbcoon = 'mysql+mysqldb://用户名:密码@数据库服务器IP:数据库端口/数据库名称'

### 安装使用
    首先你要先安装git & nmap(v6以上版本) & MySQL-python程序
    
#### CentOS
    sudo yum -y install git
    sudo yum -y install python-devel mysql-devel subversion-devel
    
    # install nmap
    # 32位系统
    sudo rpm -vhU https://nmap.org/dist/nmap-6.47-1.i386.rpm
    # 64位系统
    sudo rpm -vhU https://nmap.org/dist/nmap-6.47-1.x86_64.rpm
    
    # install pip
    wget https://pypi.python.org/packages/source/p/pip/pip-6.0.8.tar.gz
    tar zvxf pip-6.0.8.tar.gz
    cd pip-6.0.8
    python setup.py install
    
    # install MySQL-python
    pip install MySQL-python 
    
#### Kali & Ubuntu & Debian
    sudo apt-get install git
    sudo apt-get install nmap
    
    sudo apt-get install python-dev libmysqld-dev libmysqlclient-dev
    
    # install pip
    wget https://pypi.python.org/packages/source/p/pip/pip-6.0.8.tar.gz
    tar zvxf pip-6.0.8.tar.gz
    cd pip-6.0.8
    python setup.py install
    
    # install MySQL-python
    pip install MySQL-python 
    
#### 下载wyportmap项目
    git clone https://github.com/ring04h/wyportmap.git
    
#### 命令行使用
    usage: wyportmap.py targets taskid
    
    告诉wyportmap.py你的扫描目标，扫描结果会自动存入数据库
    sudo python wyportmap.py 42.62.78.70-100
    
