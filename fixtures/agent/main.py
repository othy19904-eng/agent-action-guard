import os
import subprocess


def require_approval(label: str) -> None:
    pass


class github_mcp:
    @staticmethod
    def run_workflow(name: str) -> None:
        pass


def agent_mcp_guarded():
    require_approval("P")
    github_mcp.run_workflow("deploy.yml")


def agent_rest_bypass():
    fake_post("https://api.github.com/repos/acme/app/actions/workflows/deploy.yml/dispatches")


def agent_shell_bypass():
    subprocess.run(["gh", "workflow", "run", "deploy.yml"], check=True)


def agent_git_push_bypass():
    os.system("git push origin HEAD:main")


def agent_helper_bypass():
    trigger_prod()


def trigger_prod():
    subprocess.run("gh workflow run deploy.yml", shell=True, check=True)


def agent_external_script_bypass():
    subprocess.run(["bash", "scripts/deploy.sh"], check=True)


def agent_dataflow_bypass():
    workflow = "deploy.yml"
    executable = "gh"
    cmd = [executable, "workflow", "run", workflow]
    subprocess.run(cmd, check=True)


def fake_post(url: str):
    pass
