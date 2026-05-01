import json
import time
import sys
import os
import base64
import urllib.request
import urllib.error

API_BASE = os.environ.get("AGENTPASS_API", "http://127.0.0.1:8000")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.live import Live
    from rich.text import Text
    from rich.layout import Layout
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


def _get(endpoint: str) -> dict:
    try:
        req = urllib.request.Request(f"{API_BASE}{endpoint}")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}


def _post(endpoint: str, body: dict = None) -> dict:
    try:
        data = json.dumps(body or {}).encode()
        req = urllib.request.Request(
            f"{API_BASE}{endpoint}",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}


SCENARIOS = {
    "normal": "/api/demo/normal-delegation",
    "mismatch": "/api/demo/capability-mismatch",
    "theft": "/api/demo/token-theft",
    "injection": "/api/demo/injection-defense",
    "approval": "/api/demo/human-approval",
    "escalation": "/api/demo/privilege-escalation",
}


def _decode_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) < 2:
        return {"error": "Invalid JWT format"}
    try:
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception as e:
        return {"error": str(e)}


if HAS_RICH:
    console = Console()

    def cmd_agents():
        data = _get("/api/agents")
        if isinstance(data, dict) and "error" in data:
            console.print(f"[red]Error: {data['error']}[/red]")
            return
        table = Table(title="Registered Agents", box=box.ROUNDED)
        table.add_column("Agent ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Type", style="yellow")
        table.add_column("Trust", style="magenta")
        table.add_column("Risk", style="red")
        table.add_column("SPIFFE ID", style="blue")
        table.add_column("Capabilities", style="white")
        for a in data:
            caps = ", ".join(a.get("capabilities", []))
            table.add_row(
                a.get("agent_id", ""),
                a.get("agent_name", ""),
                a.get("agent_type", ""),
                str(a.get("trust_score", 0)),
                str(round(a.get("risk_score", 0))),
                (a.get("spiffe_id", "") or "")[:40],
                caps[:50],
            )
        console.print(table)

    def cmd_tokens():
        data = _get("/api/audit/logs?limit=20&action_type=token_issue")
        if isinstance(data, dict) and "error" in data:
            console.print(f"[red]Error: {data['error']}[/red]")
            return
        table = Table(title="Recent Tokens", box=box.ROUNDED)
        table.add_column("Time", style="dim")
        table.add_column("Agent", style="cyan")
        table.add_column("Decision", style="green")
        table.add_column("Risk", style="red")
        table.add_column("Capabilities", style="white")
        for l in data:
            if l.get("decision") != "ALLOW":
                continue
            ts = time.strftime("%H:%M:%S", time.localtime(l.get("timestamp", 0)))
            caps = ", ".join(l.get("granted_capabilities", []))
            table.add_row(
                ts,
                l.get("requesting_agent", ""),
                l.get("decision", ""),
                str(l.get("risk_score", 0)),
                caps[:40],
            )
        console.print(table)

    def cmd_policies():
        data = _get("/api/policies")
        if isinstance(data, dict) and "error" in data:
            console.print(f"[red]Error: {data['error']}[/red]")
            return
        table = Table(title="Policy Rules", box=box.ROUNDED)
        table.add_column("Name", style="cyan")
        table.add_column("Effect", style="green")
        table.add_column("Priority", style="yellow")
        table.add_column("Subjects", style="white")
        table.add_column("Actions", style="magenta")
        table.add_column("Description", style="dim")
        for p in data.get("policies", []):
            effect_style = "green" if p.get("effect") == "allow" else "red"
            table.add_row(
                p.get("name", ""),
                f"[{effect_style}]{p.get('effect', '')}[/{effect_style}]",
                str(p.get("priority", 0)),
                ", ".join(p.get("subjects", []))[:30],
                ", ".join(p.get("actions", []))[:30],
                p.get("description", "")[:40],
            )
        console.print(table)

    def cmd_audit(tail: int = 30):
        data = _get(f"/api/audit/logs?limit={tail}")
        if isinstance(data, dict) and "error" in data:
            console.print(f"[red]Error: {data['error']}[/red]")
            return
        table = Table(title=f"Audit Log (Recent {tail})", box=box.ROUNDED)
        table.add_column("Time", style="dim")
        table.add_column("Agent", style="cyan")
        table.add_column("Action", style="yellow")
        table.add_column("Decision", style="green")
        table.add_column("Risk", style="red")
        table.add_column("Error", style="red")
        for l in data:
            ts = time.strftime("%H:%M:%S", time.localtime(l.get("timestamp", 0)))
            dec_style = "green" if l.get("decision") == "ALLOW" else "red"
            table.add_row(
                ts,
                l.get("requesting_agent", ""),
                l.get("action_type", ""),
                f"[{dec_style}]{l.get('decision', '')}[/{dec_style}]",
                str(l.get("risk_score", 0)),
                l.get("error_code", ""),
            )
        console.print(table)

    def cmd_threats():
        data = _get("/api/system/threat-summary")
        if isinstance(data, dict) and "error" in data:
            console.print(f"[red]Error: {data['error']}[/red]")
            return
        s = data.get("summary", {})
        console.print(Panel(
            f"[bold]24h Threat Summary[/bold]\n"
            f"Total: [red]{s.get('total_threats_24h', 0)}[/red]  "
            f"Critical: [red]{s.get('critical_count', 0)}[/red]  "
            f"High: [yellow]{s.get('high_count', 0)}[/yellow]",
            title="Threat Dashboard",
            border_style="red",
        ))

    def cmd_circuit_breakers():
        data = _get("/api/circuit-breakers")
        if isinstance(data, dict) and "error" in data:
            console.print(f"[red]Error: {data['error']}[/red]")
            return
        table = Table(title="Circuit Breakers", box=box.ROUNDED)
        table.add_column("Agent", style="cyan")
        table.add_column("State", style="yellow")
        table.add_column("Failures", style="red")
        table.add_column("Last Error", style="dim")
        for aid, cb in data.items():
            state_style = "green" if cb.get("state") == "CLOSED" else "red" if cb.get("state") == "OPEN" else "yellow"
            table.add_row(
                aid,
                f"[{state_style}]{cb.get('state', '')}[/{state_style}]",
                str(cb.get("failure_count", 0)),
                cb.get("last_failure_type", ""),
            )
        console.print(table)

    def cmd_rate_limits():
        data = _get("/api/rate-limits")
        if isinstance(data, dict) and "error" in data:
            console.print(f"[red]Error: {data['error']}[/red]")
            return
        table = Table(title="Rate Limits", box=box.ROUNDED)
        table.add_column("Agent", style="cyan")
        table.add_column("Action", style="yellow")
        table.add_column("Current", style="white")
        table.add_column("Limit", style="red")
        table.add_column("Remaining", style="green")
        for aid, actions in data.items():
            for action, stats in actions.items():
                table.add_row(
                    aid,
                    action,
                    str(stats.get("current_count", 0)),
                    str(stats.get("limit", 0)),
                    str(stats.get("remaining", 0)),
                )
        console.print(table)

    def _run_single_demo(scenario: str):
        if scenario not in SCENARIOS:
            console.print(f"[red]Unknown scenario: {scenario}[/red]")
            console.print(f"Available: {', '.join(SCENARIOS.keys())}")
            return False

        console.print(f"[bold cyan]Running demo: {scenario}[/bold cyan]")
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("Executing...", total=None)
            data = _post(SCENARIOS[scenario])
            progress.update(task, completed=True)

        if isinstance(data, dict) and "error" in data:
            console.print(f"[red]Error: {data['error']}[/red]")
            return False

        steps = data.get("steps", [])
        for step in steps:
            s = step.get("step", "?")
            desc = step.get("description", "")
            action = step.get("action", "")
            if "error" in action or "denied" in action or "blocked" in action:
                console.print(f"  [red]Step {s}:[/red] {desc}")
            elif "approval" in action:
                console.print(f"  [yellow]Step {s}:[/yellow] {desc}")
            else:
                console.print(f"  [green]Step {s}:[/green] {desc}")

        console.print(f"[bold green]Demo '{scenario}' completed![/bold green]")
        return True

    def cmd_demo(scenario: str):
        _run_single_demo(scenario)

    def cmd_run_all():
        console.print("[bold magenta]Running all 6 demo scenarios...[/bold magenta]\n")
        results = {}
        for scenario in SCENARIOS:
            console.rule(f"[bold]Scenario: {scenario}[/bold]")
            ok = _run_single_demo(scenario)
            results[scenario] = ok
            console.print()
            time.sleep(0.5)

        console.rule("[bold]Summary[/bold]")
        passed = sum(1 for v in results.values() if v)
        total = len(results)
        for s, ok in results.items():
            icon = "[green]✓[/green]" if ok else "[red]✗[/red]"
            console.print(f"  {icon} {s}")
        console.print(f"\n[bold]{passed}/{total} scenarios completed[/bold]")

    def cmd_token_decode(token_str: str):
        payload = _decode_jwt_payload(token_str)
        if "error" in payload:
            console.print(f"[red]Decode error: {payload['error']}[/red]")
            return
        table = Table(title="JWT Payload", box=box.ROUNDED)
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        for k, v in payload.items():
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            table.add_row(str(k), str(v))
        console.print(table)

    def cmd_metrics():
        data = _get("/api/system/metrics")
        if isinstance(data, dict) and "error" in data:
            console.print(f"[red]Error: {data['error']}[/red]")
            return
        console.print(Panel(
            f"[bold]System Metrics[/bold]\n"
            f"Agents: [cyan]{data.get('agents', {}).get('total', 0)}[/cyan]  "
            f"Active Tokens: [green]{data.get('tokens', {}).get('active', 0)}[/green]  "
            f"Revoked: [red]{data.get('tokens', {}).get('revoked', 0)}[/red]\n"
            f"ALLOW: [green]{data.get('audit', {}).get('allow_count', 0)}[/green]  "
            f"DENY: [red]{data.get('audit', {}).get('deny_count', 0)}[/red]  "
            f"ALERT: [yellow]{data.get('audit', {}).get('alert_count', 0)}[/yellow]  "
            f"Injection: [red]{data.get('audit', {}).get('injection_count', 0)}[/red]",
            title="System Overview",
            border_style="cyan",
        ))

    def cmd_verify_chain():
        data = _get("/api/audit/verify")
        if isinstance(data, dict) and "error" in data:
            console.print(f"[red]Error: {data['error']}[/red]")
            return
        if data.get("valid"):
            console.print(f"[green]✓ Audit chain valid ({data.get('total_records', 0)} records)[/green]")
        else:
            console.print(f"[red]✗ Chain broken at record {data.get('broken_at_id', '?')}[/red]")

    def main():
        if len(sys.argv) < 2:
            console.print("[bold]AgentIam CLI[/bold]")
            console.print("Commands:")
            console.print("  agents              List all agents")
            console.print("  tokens              List recent tokens")
            console.print("  policies            List policy rules")
            console.print("  audit [--tail N]    View audit log (default 30)")
            console.print("  threats             Threat summary")
            console.print("  circuit-breakers    Circuit breaker states")
            console.print("  rate-limits         Rate limit stats")
            console.print("  metrics             System metrics")
            console.print("  verify-chain        Verify audit chain")
            console.print("  run <scenario>      Run a demo scenario")
            console.print("  run all             Run all 6 demo scenarios")
            console.print("  token decode <jwt>  Decode a JWT token")
            console.print(f"\nDemo scenarios: {', '.join(SCENARIOS.keys())}")
            return

        cmd = sys.argv[1]

        if cmd == "run":
            scenario = sys.argv[2] if len(sys.argv) > 2 else "normal"
            if scenario == "all":
                cmd_run_all()
            else:
                cmd_demo(scenario)
        elif cmd == "demo":
            scenario = sys.argv[2] if len(sys.argv) > 2 else "normal"
            cmd_demo(scenario)
        elif cmd == "audit":
            tail = 30
            for i, arg in enumerate(sys.argv[2:], 2):
                if arg == "--tail" and i + 1 < len(sys.argv):
                    try:
                        tail = int(sys.argv[i + 1])
                    except ValueError:
                        pass
            cmd_audit(tail)
        elif cmd == "token":
            subcmd = sys.argv[2] if len(sys.argv) > 2 else ""
            if subcmd == "decode" and len(sys.argv) > 3:
                cmd_token_decode(sys.argv[3])
            else:
                console.print("[red]Usage: token decode <jwt>[/red]")
        elif cmd == "agents":
            cmd_agents()
        elif cmd == "tokens":
            cmd_tokens()
        elif cmd == "policies":
            cmd_policies()
        elif cmd == "threats":
            cmd_threats()
        elif cmd == "circuit-breakers":
            cmd_circuit_breakers()
        elif cmd == "rate-limits":
            cmd_rate_limits()
        elif cmd == "metrics":
            cmd_metrics()
        elif cmd == "verify-chain":
            cmd_verify_chain()
        else:
            console.print(f"[red]Unknown command: {cmd}[/red]")

else:
    def main():
        if len(sys.argv) < 2:
            print("AgentIam CLI (install 'rich' for enhanced output)")
            print("Commands: agents, tokens, policies, audit [--tail N], threats, circuit-breakers,")
            print("          rate-limits, metrics, verify-chain, run <scenario>, run all, token decode <jwt>")
            return

        cmd = sys.argv[1]

        if cmd == "run":
            scenario = sys.argv[2] if len(sys.argv) > 2 else "normal"
            if scenario == "all":
                for s in SCENARIOS:
                    print(f"\n=== Scenario: {s} ===")
                    data = _post(SCENARIOS[s])
                    for step in data.get("steps", []):
                        print(f"  Step {step.get('step','?')}: {step.get('description','')}")
            else:
                data = _post(SCENARIOS.get(scenario, SCENARIOS["normal"]))
                for step in data.get("steps", []):
                    print(f"  Step {step.get('step','?')}: {step.get('description','')}")
        elif cmd == "demo":
            scenario = sys.argv[2] if len(sys.argv) > 2 else "normal"
            data = _post(SCENARIOS.get(scenario, SCENARIOS["normal"]))
            for step in data.get("steps", []):
                print(f"  Step {step.get('step','?')}: {step.get('description','')}")
        elif cmd == "audit":
            tail = 30
            for i, arg in enumerate(sys.argv[2:], 2):
                if arg == "--tail" and i + 1 < len(sys.argv):
                    try:
                        tail = int(sys.argv[i + 1])
                    except ValueError:
                        pass
            data = _get(f"/api/audit/logs?limit={tail}")
            for l in data:
                ts = time.strftime("%H:%M:%S", time.localtime(l.get("timestamp", 0)))
                print(f"  {ts} | {l.get('requesting_agent','')} | {l.get('action_type','')} | {l.get('decision','')}")
        elif cmd == "token":
            subcmd = sys.argv[2] if len(sys.argv) > 2 else ""
            if subcmd == "decode" and len(sys.argv) > 3:
                payload = _decode_jwt_payload(sys.argv[3])
                for k, v in payload.items():
                    print(f"  {k}: {v}")
            else:
                print("Usage: token decode <jwt>")
        elif cmd == "agents":
            data = _get("/api/agents")
            for a in data:
                print(f"  {a.get('agent_id','')} | {a.get('agent_name','')} | trust={a.get('trust_score',0)} risk={a.get('risk_score',0)}")
        elif cmd == "metrics":
            data = _get("/api/system/metrics")
            print(f"Agents: {data.get('agents',{}).get('total',0)} | Active Tokens: {data.get('tokens',{}).get('active',0)} | DENY: {data.get('audit',{}).get('deny_count',0)}")
        elif cmd == "verify-chain":
            data = _get("/api/audit/verify")
            print(f"Chain valid: {data.get('valid', False)} | Records: {data.get('total_records', 0)}")
        else:
            print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
