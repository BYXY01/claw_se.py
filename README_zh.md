# claw_se

**claw_se（Small + Security 版）**——一个单文件、安全优先的个人 AI 助理。名字是双关：**S**mall（单文件、极简体积）+ **S**ecurity（每个动作都过安全内核）。

[![python](https://img.shields.io/badge/python-3.10%2B-blue)](https://gitee.com/baiyun_xy001/claw_se.py) [![status](https://img.shields.io/badge/status-experimental-orange)](https://gitee.com/baiyun_xy001/claw_se.py) [![version](https://img.shields.io/badge/version-0.0.102--%CE%B1-blue)](https://gitee.com/baiyun_xy001/claw_se.py) [![license](https://img.shields.io/badge/license-planned-lightgrey)](https://gitee.com/baiyun_xy001/claw_se.py)

---

## 共同的起源

Claw 系列有一个共同的起源：26 年初 [OpenClaw](https://gitee.com/openclaw-cn/openclaw-cn) 爆火，同时我们开始接触 [LangChain](https://gitee.com/langchain-ai/langchain) 框架，展开一系列实验。其中一次测试把**终端当 `@tool` 接入 Agent**，产生了让人惊讶的效果——程序在自我修改迭代，仅仅 2 天就生长出文件、进程、自我感知等一系列功能，越来越接近 AI-cli 工具，于是启发了两个方向：

- **claw_se**——功能确定的安全版：追求确定性与安全，开箱即用。
- **[Claw_EE](https://gitee.com/baiyun_xy001/Claw_EE.py)**——种子版：几十行代码，自读/自改/自重启，能长出任意功能。

最早的初代原型只有 **37 行**（去掉空行 30 行）：把上课样例的工具换成了 command 执行。作者在运行输入框让程序"读自己的代码，怎么加多轮对话？"——它给出了新版且多轮对话完全正常。"作业自己迭代了自己"。

---

## 介绍

当前这是 **0.0.102-α**。SE = Small + Security（也是 Simple / Smart / Shield）。

特性：

- **单文件分发**——`builder.py` 把 `src_dev/` 合并成一个 `claw_se.py`；首启自释放 `modules/`、`config/`、`prompt_library/` 并自动安装核心依赖。Windows 只以 `claw_se.exe`（PyInstaller onefile）发布：在 Windows 上裸跑 `python claw_se.py` 会被拒绝启动。
- **安全内核（双开关 + 三名单）**——静态防火墙（黑名单/自学习，0 Token）+ LLM 智能安全裁判（可自学习，"一次识别，永久免疫"）。白名单只免 LLM，永不免静态检查。自指防御把脚本/模块目录写保护。
- **多通道 MsgIO 总线**——阻塞渠道（终端、IM 长连接）由线程桥接，多通道共存不冻结主循环；安全询问按请求来源渠道路由。
- **模块化 Agent（LangChain/LangGraph + checkpoint + 自动摘要）**——模块：`exec`（前台+后台进程）、`file`（无状态操作 + rollback）、`info`、`delegate`（最小权限子模型委派）、`memory`（opt-in）。
- **输入层注入防护**——每次 `receive()` 先过 `input_guard`，注入被拦截并回显，到不了主循环。

> ⚠️ **实验版本**——本项目当前为实验版本。

---

## 使用

```bash
# 构建单文件（产物在 dist/）
python3 builder.py --out dist
python3 builder.py --exe --out dist   # Windows: 生成 claw_se.exe

# 运行（首启自释放 modules/config/prompts + 自动装依赖）
python dist/claw_se.py

# 测试（离线，无需 API Key）
python3 -m pytest tests/unit_tests -q
python3 -m pyflakes src_dev tests builder.py
```

配置：`config/providers.json`（从 `src_dev/config/providers.example.json` 复制）、`.env`（API Key，`key_ref` 指针，永不入库）、`config/modules.json` / `config/security.json`（模块启停与安全开关，首启由代码默认自动生成）。

---

## 时间线

- **26 年初**——[OpenClaw](https://gitee.com/openclaw-cn/openclaw-cn) 爆火，开始接触 LangChain：从最简非流式 agent 起步，再接上工具（天气、计算器），最后把**终端当 `@tool` 接入 Agent**——程序开始自我修改迭代，仅仅 2 天就生长出文件、进程、自我感知等功能，越来越接近 AI-cli 工具。
- **智能体演进**：最简 agent → 带工具（天气/计算器）→ 终端即工具（37 行初代）→ 当夜自迭代出多轮版 → 流式 / 多模型 / 图结构 / 记忆（从 AgentExecutor 逐步走向 LangGraph）→ 安全版构想 → SE/EE 路线分立（MiniClaw → Security Claw → claw_se.py）。
- **阶梯 0-4**——骨架 / 安全内核 / 基础模块 / 委派+记忆 / 单文件分发。
- **0.0.100**——单文件版本化、无状态 file 工具、psutil 进程树 kill。
- **0.0.101**——msgio 多通道、确定性进程树 kill、Windows 必须 exe、GitHub CI + 自动发布。
- **0.0.102**——安装型插件加载器（manifest + 门面 + 分级校验）、requirements.txt 作为依赖单一事实源、实验性 unix 二进制参数、Gitee 自动化。
- **路线图**——多通道（已完成）→ 插件加载器（已完成）→ 真实渠道 + 供应商故障转移 → [OpenClaw](https://gitee.com/openclaw-cn/openclaw-cn) 桥 → 会话内记忆。

---

## 许可

规划中，留意仓库。

---

## 鸣谢

- **[OpenClaw](https://gitee.com/openclaw-cn/openclaw-cn)**——启发。
- **[LangChain](https://gitee.com/langchain-ai/langchain)**——框架基础（Tool/AgentExecutor、LangGraph）。
- 上课的样例代码——一切的起点。
