#!/usr/bin/env bash
set -euo pipefail

SESSION="${SESSION:-aiops}"
NS_MON="${NS_MON:-monitoring}"
NS_APP="${NS_APP:-default}"

SVC_PROM="${SVC_PROM:-kube-prometheus-stack-prometheus}"   # svc/<name>
SVC_GRAF="${SVC_GRAF:-kube-prometheus-stack-grafana}"       # svc/<name>
SVC_LOKI="${SVC_LOKI:-loki}"                                # svc/<name>
SVC_APP="${SVC_APP:-flask-demo}"                            # svc/<name>

PORT_PROM="${PORT_PROM:-9090}"
PORT_GRAF="${PORT_GRAF:-3000}"
PORT_LOKI="${PORT_LOKI:-3100}"
PORT_APP="${PORT_APP:-8080}"

KUBECTL="${KUBECTL:-kubectl}"
UV="${UV:-uv}"

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "tmux session '$SESSION' already exists. Attaching..."
  tmux attach -t "$SESSION"
  exit 0
fi

tmux new-session -d -s "$SESSION" -n "aiops"

# 让 pane 标题显示出来（好监控）
tmux set -g pane-border-status top
tmux set -g pane-border-format "#{pane_title}"

# --- 创建 6 个 pane，并捕获 pane_id ---
P0="$(tmux display-message -p "#{pane_id}")"

# 右侧
P1="$(tmux split-window -h -P -F "#{pane_id}")"
# 左下
tmux select-pane -t "$P0"
P2="$(tmux split-window -v -P -F "#{pane_id}")"
# 右下
tmux select-pane -t "$P1"
P3="$(tmux split-window -v -P -F "#{pane_id}")"
# 再切到左下，再往下开一个（logs）
tmux select-pane -t "$P2"
P4="$(tmux split-window -v -P -F "#{pane_id}")"
# 再切到右下，再往下开一个（aiops watch）
tmux select-pane -t "$P3"
P5="$(tmux split-window -v -P -F "#{pane_id}")"

# --- 设置标题 ---
tmux select-pane -t "$P0" -T "Prometheus :${PORT_PROM}"
tmux select-pane -t "$P1" -T "Grafana :${PORT_GRAF}"
tmux select-pane -t "$P2" -T "Loki :${PORT_LOKI}"
tmux select-pane -t "$P3" -T "App :${PORT_APP}"
tmux select-pane -t "$P4" -T "Logs (app=${SVC_APP})"
tmux select-pane -t "$P5" -T "AIOps watch"

# --- 下发命令（严格按 pane_id） ---
tmux send-keys -t "$P0" \
  "bash -lc 'echo \"[Prometheus] http://localhost:${PORT_PROM}\"; ${KUBECTL} -n ${NS_MON} port-forward svc/${SVC_PROM} ${PORT_PROM}:9090; tmux kill-session -t ${SESSION}'" C-m

tmux send-keys -t "$P1" \
  "bash -lc 'echo \"[Grafana] http://localhost:${PORT_GRAF}\"; ${KUBECTL} -n ${NS_MON} port-forward svc/${SVC_GRAF} ${PORT_GRAF}:80; tmux kill-session -t ${SESSION}'" C-m

tmux send-keys -t "$P2" \
  "bash -lc 'echo \"[Loki] http://localhost:${PORT_LOKI}\"; ${KUBECTL} -n ${NS_MON} port-forward svc/${SVC_LOKI} ${PORT_LOKI}:3100; tmux kill-session -t ${SESSION}'" C-m

tmux send-keys -t "$P3" \
  "bash -lc 'echo \"[App] http://localhost:${PORT_APP}\"; ${KUBECTL} -n ${NS_APP} port-forward svc/${SVC_APP} ${PORT_APP}:8080; tmux kill-session -t ${SESSION}'" C-m

tmux send-keys -t "$P4" \
  "bash -lc 'echo \"[App logs]\"; ${KUBECTL} -n ${NS_APP} logs -l app.kubernetes.io/instance=${SVC_APP} -f --tail=8080; tmux kill-session -t ${SESSION}'" C-m

tmux send-keys -t "$P5" \
  "bash -lc 'echo \"[AIOps] every 20s\"; watch -n 20 \"${UV} run aiops incident\"; tmux kill-session -t ${SESSION}'" C-m

# 让布局更紧凑（你也可以换 main-vertical / main-horizontal）
tmux select-layout -t "$SESSION:0" tiled

tmux attach -t "$SESSION"

#if ! tmux has-session -t "$SESSION" 2>/dev/null; then
#  exec "$SCRIPT_PATH"
#fi
