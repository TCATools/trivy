# -*- coding: utf-8 -*-
"""
trivy: 安全扫描工具
功能: 代码分析
用法: python3 main.py
"""


import os
import json
import subprocess
import sys

vul_serverity_map = {
    "LOW": "VUL_INFO",
    "MEDIUM": "VUL_WARN",
    "HIGH": "VUL_ERROR",
    "CRITICAL": "VUL_ERROR"
}

sec_serverity_map = {
    "LOW": "SEC_INFO",
    "MEDIUM": "SEC_WARN",
    "HIGH": "SEC_ERROR",
    "CRITICAL": "SEC_ERROR"
}

class Trivy(object):
    def __get_task_params(self):
        """获取需要任务参数
        :return:
        """
        task_request_file = os.environ.get("TASK_REQUEST")
        # task_request_file = "task_request.json"
        with open(task_request_file, 'r') as rf:
            task_request = json.load(rf)
        task_params = task_request["task_params"]

        return task_params

    def run(self):
        """
        :return:
        """
        # 代码目录直接从环境变量获取
        source_dir = os.environ.get("SOURCE_DIR", None)
        print("[debug] source_dir: %s" % source_dir)
        # 其他参数从task_request.json文件获取
        task_params = self.__get_task_params()
        # 环境变量
        envs = task_params["envs"]
        print("[debug] envs: %s" % envs)
        # 规则
        rules = task_params["rules"]

        result = []
        if sys.platform not in ("linux", "linux2"):
            print("[ERROR]: 目前支持linux系统, 返回空结果")
            with open("result.json", "w") as fp:
                json.dump(result, fp, indent=2, ensure_ascii=False)
            return result

        error_output = "error_output.json"
        cmd = [
            "./bin/trivy",
            "fs",
            "--format",
            "json",
            "--output",
            error_output,
            source_dir
        ]

        scan_cmd = " ".join(cmd)
        print("[debug] cmd: %s" % scan_cmd)
        subproc = subprocess.Popen(scan_cmd, shell=True)
        subproc.communicate()

        try:
            with open(error_output, "r") as fs:
                outputs_data = json.load(fs)
        except:
            print("[ERROR]: 无法打开结果文件, 返回空结果")
            with open("result.json", "w") as fp:
                json.dump(result, fp, indent=2, ensure_ascii=False)
            return []

        for res_info in outputs_data.get("Results", []):
            path = res_info["Target"]
            if res_info["Class"] == "lang-pkgs":
                for vul in res_info.get("Vulnerabilities", []):
                    issue = {
                        "column": 0,
                        "line": 0,
                        "path": path,
                        "refs": [],
                    }
                    rule = vul_serverity_map.get(vul["Severity"], None)
                    if (not rule) or (rule not in rules):
                        continue
                    issue["rule"] = rule
                    issue["msg"] = "%s@%s组件发现漏洞:%s，请尽快升级到fixed版本:%s" % (
                        vul["PkgName"],
                        vul["InstalledVersion"],
                        vul["Title"],
                        vul.get("FixedVersion", ""),
                    )
                    result.append(issue)
            if res_info["Class"] == "secret":
                for sec in res_info.get("Secrets", []):
                    issue = {
                        "column": 0,
                        "line": sec["StartLine"],
                        "path": path,
                        "refs": [],
                    }
                    rule = sec_serverity_map.get(sec["Severity"], None)
                    if (not rule) or (rule not in rules):
                        continue
                    issue["rule"] = rule
                    issue["msg"] = "规则%s:%s，发现敏感信息:%s" % (
                        sec["RuleID"],
                        sec["Title"],
                        sec["Match"],
                    )
                    result.append(issue)

        with open("result.json", "w") as fp:
            json.dump(result, fp, indent=2, ensure_ascii=False)

if __name__ == '__main__':
    print("-- start run tool ...")
    Trivy().run()
    print("-- end ...")
