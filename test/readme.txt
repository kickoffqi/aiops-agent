我们新增 4 个 endpoint（或一个 endpoint 带 mode）：
	1.	依赖不可用：/dep?url=http://10.0.0.1:5432（连接超时/拒绝）
    curl -i "http://localhost:8080/dep?host=10.0.0.1&port=5432&timeout=0.2"
    curl -i "http://localhost:8080/dep?host=10.0.0.1&port=5432&timeout=0.2"
	2.	配置错误：/config（读取必需 env，缺失则 500）
    curl -i "http://localhost:8080/config"
	3.	资源问题：/cpu（忙等 CPU）、/mem（分配内存）、/slow（延迟）
    curl -i "http://localhost:8080/cpu?seconds=0.8"
    curl -i "http://localhost:8080/mem?mb=200"
    curl -i "http://localhost:8080/slow"
    4.  发现没有分类的 unknown 错误
    curl -i "http://localhost:8080/unknown"



    
	5.	CrashLoop：通过环境变量 CRASH_ON_START=1 让容器启动后退出（模拟 CrashLoopBackOff）
        #Check Crash:
        kubectl -n default set env deploy/flask-demo CRASH_ON_START=1
        kubectl -n default rollout status deploy/flask-demo
        kubectl -n default get pods -l app=flask-demo -w

        #Turn off Crash
        kubectl -n default set env deploy/flask-demo CRASH_ON_START-
        kubectl -n default rollout status deploy/flask-demo