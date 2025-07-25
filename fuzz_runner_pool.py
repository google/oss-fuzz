#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
fuzz_runner_pool.py

并行批量执行 OSS-Fuzz 本地测试全流程。使用 multiprocessing.Pool 将项目
分发到多个 CPU核心上同时处理。

用法: python3 fuzz_runner_pool.py [项目列表文件] [--sanitizer 类型] [--workers N]
示例: python3 fuzz_runner_pool.py valid_projects.txt --workers 4
"""

import os
import sys
import subprocess
import argparse
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple
from multiprocessing import Pool, cpu_count

# --- 全局配置 (可通过命令行参数覆盖) ---
HOME_DIR = Path.home()
OSS_FUZZ_DIR = HOME_DIR / "FuzzAug" / "fuzz"/"oss-fuzz"
LOG_DIR = OSS_FUZZ_DIR / "script_pool_batch_logs"

def setup_logging(project_name: str) -> Path:
    """为单个项目创建带时间戳的日志文件."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        LOG_DIR.chmod(0o777)
    except PermissionError:
        # 在并行环境中，这里可能会有多个进程同时尝试，打印一次警告即可
        pass
        
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    log_file_path = LOG_DIR / f"oss_fuzz_{project_name}_{timestamp}.log"
    return log_file_path

def log_and_print(message: str, log_file: Path, to_stdout: bool = True):
    """将消息写入日志文件，并根据需要打印到控制台。"""
    if to_stdout:
        # 添加进程ID，以便区分并行输出
        print(f"[PID:{os.getpid()}] {message}")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(message + "\n")

def run_command(
    cmd: str, 
    log_msg: str, 
    log_file: Path, 
    allowed_exit_codes: Optional[List[int]] = None,
    auto_confirm: bool = True  # 新增自动确认参数
) -> bool:
    """执行一个 shell 命令，并将输出实时流式传输到日志文件。"""
    if allowed_exit_codes is None:
        allowed_exit_codes = []

    log_and_print(f"▶️  {log_msg}...", log_file, to_stdout=False)
    log_and_print(f"   $ {cmd}", log_file, to_stdout=False)

    try:
        # 添加自动确认机制
        if auto_confirm:
            cmd = f"yes | {cmd}"

        process = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding='utf-8', errors='replace', bufsize=1
        )
        
        with open(log_file, "a", encoding="utf-8") as f:
            for line in iter(process.stdout.readline, ''):
                f.write(line) # 只写入日志，避免控制台输出混乱

        process.wait()
        exit_code = process.returncode

        if exit_code == 0:
            log_and_print(f"✅ 命令成功完成。", log_file, to_stdout=False)
            return True
        elif exit_code in allowed_exit_codes:
            log_and_print(f"ℹ️  命令以预期状态退出: {exit_code}", log_file, to_stdout=False)
            return True
        else:
            log_and_print(f"❌ 命令执行失败 (退出码: {exit_code})", log_file)
            return False
    except Exception as e:
        log_and_print(f"💥 执行命令时发生异常: {e}", log_file)
        return False

def discover_fuzz_targets(project_name: str) -> List[str]:
    """自动发现 Fuzz 目标。"""
    project_out_dir = OSS_FUZZ_DIR / "build" / "out" / project_name
    project_src_dir = OSS_FUZZ_DIR / "projects" / project_name
    targets = []

    if project_out_dir.is_dir():
        for f in project_out_dir.iterdir():
            if (f.is_file() and os.access(f, os.X_OK) and 
                f.name.startswith("fuzz_") and '.' not in f.name):
                targets.append(f.name)

    if not targets and project_src_dir.is_dir():
        for py_file in project_src_dir.glob("fuzz_*.py"):
            try:
                with open(py_file, "r", encoding="utf-8") as f:
                    if "atheris.Setup" in f.read():
                        targets.append(py_file.stem)
            except Exception as e:
                # 在worker进程中，只打印到自己的日志
                print(f"⚠️  警告: 读取文件 {py_file} 失败: {e}")
    return targets

def run_project_workflow(project_name: str, sanitizer: str) -> Tuple[bool, str]:
    """
    处理单个项目的完整工作流 (Worker Function)。
    此函数由进程池中的每个工作进程独立执行。
    
    Returns:
        一个元组 (is_success: bool, project_name: str)
    """
    log_file = setup_logging(project_name)
    
    # 在 worker 的开头打印，以便追踪
    log_and_print("=" * 60, log_file)
    log_and_print(f"🚀 开始处理项目: {project_name}", log_file)
    log_and_print(f"📝 日志文件: {log_file}", log_file)
    log_and_print("=" * 60, log_file)
    
    # 每个进程都需要设置自己的工作目录
    try:
        os.chdir(OSS_FUZZ_DIR)
    except FileNotFoundError:
        log_and_print(f"❌ 严重错误: OSS-Fuzz 目录 '{OSS_FUZZ_DIR}' 不存在！", log_file)
        return (False, project_name)

    # 步骤 1: 构建Docker镜像（启用自动确认）
    if not run_command(
        f"python3 infra/helper.py build_image {project_name}",
        f"步骤1/5: 构建 {project_name} 的Docker镜像", log_file,
        auto_confirm=True  # 自动确认所有提示
    ):
        log_and_print(f"❌ 项目 {project_name} 构建镜像失败", log_file)
        return (False, project_name)

    # 步骤 2: 编译带检测器的fuzzer（启用自动确认）
    if not run_command(
        f"python3 infra/helper.py build_fuzzers --sanitizer {sanitizer} {project_name}",
        f"步骤2/5: 编译 {project_name} 的fuzzer (sanitizer={sanitizer})", log_file,
        auto_confirm=True  # 自动确认所有提示
    ):
        log_and_print(f"❌ 项目 {project_name} 编译fuzzer失败", log_file)
        return (False, project_name)

    # 步骤 3: 自动发现目标
    log_and_print(f"🔍 正在为 {project_name} 自动发现fuzz目标...", log_file)
    fuzz_targets = discover_fuzz_targets(project_name)

    if not fuzz_targets:
        log_and_print(f"⚠️  警告: {project_name} 未找到任何fuzz目标！跳过运行步骤。", log_file)
        return (True, project_name)
    
    log_and_print(f"✅ 发现目标: {', '.join(fuzz_targets)}", log_file)

    # 步骤 4: 遍历运行所有目标（启用自动确认）
    for i, target in enumerate(fuzz_targets, 1):
        run_command(
            f"python3 infra/helper.py run_fuzzer {project_name} {target} -- -max_total_time=60",
            f"步骤4/{len(fuzz_targets)}: 运行目标 [{target}] (60秒)", log_file,
            allowed_exit_codes=[1, 124],
            auto_confirm=True  # 自动确认所有提示
        )

    # 步骤 5: 生成覆盖率报告 (暂无)
    log_and_print("步骤5/5: 生成覆盖率报告 (当前版本暂未实现)", log_file)
    log_and_print(f"✅ 项目 {project_name} 处理完成！", log_file)
    return (True, project_name)

def main():
    """
    主流程函数：设置进程池并分发任务。
    """
    parser = argparse.ArgumentParser(
        description="OSS-Fuzz 并行批量测试工具",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="示例:\n  python3 fuzz_runner_parallel.py valid_projects.txt --workers 4\n  python3 fuzz_runner_parallel.py my_projects.txt --sanitizer undefined"
    )
    parser.add_argument(
        "project_list_file", nargs="?", default="valid_projects.txt",
        help="包含待测试项目列表的文本文件。(默认: valid_projects.txt)"
    )
    parser.add_argument(
        "--sanitizer", default="address", choices=["address", "memory", "undefined", "coverage"],
        help="要使用的 sanitizer 类型。(默认: address)"
    )
    parser.add_argument(
        "--workers", type=int, default=cpu_count(),
        help=f"并发执行的工作进程数。(默认: 系统CPU核心数, 即 {cpu_count()})"
    )
    args = parser.parse_args()
    
    # --- 环境检查 ---
    if not OSS_FUZZ_DIR.is_dir():
        print(f"❌ 错误: OSS-Fuzz 目录 '{OSS_FUZZ_DIR}' 不存在！")
        sys.exit(1)
    
    project_list_path = Path(args.project_list_file)
    if not project_list_path.is_file():
        print(f"❌ 错误: 项目列表文件 '{project_list_path}' 不存在！")
        sys.exit(1)
        
    print(f"✅ 环境检查通过。将使用 {args.workers} 个并行工作进程。")

    # --- 读取和准备任务 ---
    try:
        with open(project_list_path, "r", encoding="utf-8") as f:
            projects = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    except Exception as e:
        print(f"❌ 读取项目列表文件时出错: {e}")
        sys.exit(1)
        
    if not projects:
        print("⚠️  警告: 项目列表为空，无可执行任务。")
        sys.exit(0)

    # 为 starmap 准备任务参数列表，每个项目都是一个 (project_name, sanitizer) 元组
    tasks = [(project, args.sanitizer) for project in projects]
    total_projects = len(tasks)
    
    print(f"\n🚀 即将并行处理 {total_projects} 个项目...")

    # --- 执行并行处理 ---
    # 使用 with 语句确保进程池被正确关闭
    with Pool(processes=args.workers) as pool:
        # starmap 会阻塞直到所有任务完成
        # 它将 tasks 列表中的每个元组解包作为参数传递给 worker 函数
        results = pool.starmap(run_project_workflow, tasks)

    # --- 收集并打印结果 ---
    failed_projects = []
    for success, project_name in results:
        if success:
            print(f"✅ 项目 {project_name} 成功完成")
        else:
            print(f"❌ 项目 {project_name} 处理失败")
            failed_projects.append(project_name)

    # --- 最终总结 ---
    fail_count = len(failed_projects)
    success_count = total_projects - fail_count
    
    print("\n" + "=" * 60)
    print("🎉 批量处理完成！")
    print(f"📊 总计: {total_projects} 个项目")
    print(f"✅ 成功: {success_count}")
    print(f"❌ 失败: {fail_count}")

    if failed_projects:
        print("📛 失败项目列表:")
        for proj in sorted(failed_projects):
            print(f"  • {proj}")
        print("\n💡 提示: 失败项目的详细信息请查看对应的日志文件。")
        print(f"   日志目录: {LOG_DIR}")

if __name__ == "__main__":
    # 在 Windows 或 macOS 的某些 Python 版本上，需要将 main 调用放在这个保护块中
    # 以防止子进程重新导入和执行主模块代码，导致无限递归。
    main()