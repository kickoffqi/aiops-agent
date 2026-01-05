我们新增 4 个 endpoint（或一个 endpoint 带 mode）：
	1.	依赖不可用：/dep?url=http://10.0.0.1:5432（连接超时/拒绝）
	2.	配置错误：/config（读取必需 env，缺失则 500）
	3.	资源问题：/cpu（忙等 CPU）、/mem（分配内存）、/slow（延迟）
	4.	CrashLoop：通过环境变量 CRASH_ON_START=1 让容器启动后退出（模拟 CrashLoopBackOff）