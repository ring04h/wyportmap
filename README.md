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

### 命令行使用
    usage: wyportmap.py targets taskid
    
    首先你要先安装nmap程序
    sudo yum -y install nmap
    
    告诉wyportmap.py你的扫描目标，扫描结果会自动存入数据库
    sudo python wyportmap.py 42.42.42.42-52
    
