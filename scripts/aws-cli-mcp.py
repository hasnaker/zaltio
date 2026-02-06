#!/usr/bin/env python3
"""
AWS CLI MCP Server for Zalt
Provides CloudFormation stack management including delete operations
"""

import json
import subprocess
import sys
from typing import Any

def run_aws_command(args: list[str]) -> dict[str, Any]:
    """Run AWS CLI command and return result"""
    try:
        result = subprocess.run(
            ["aws"] + args,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode == 0:
            try:
                output = json.loads(result.stdout) if result.stdout.strip() else {}
            except json.JSONDecodeError:
                output = {"message": result.stdout.strip()}
            return {"success": True, "data": output}
        else:
            return {"success": False, "error": result.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timed out after 300 seconds"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def delete_stack(stack_name: str, region: str = "eu-central-1") -> dict:
    """Delete CloudFormation stack"""
    return run_aws_command([
        "cloudformation", "delete-stack",
        "--stack-name", stack_name,
        "--region", region
    ])

def describe_stack(stack_name: str, region: str = "eu-central-1") -> dict:
    """Describe CloudFormation stack"""
    return run_aws_command([
        "cloudformation", "describe-stacks",
        "--stack-name", stack_name,
        "--region", region
    ])

def list_stacks(region: str = "eu-central-1") -> dict:
    """List CloudFormation stacks"""
    return run_aws_command([
        "cloudformation", "list-stacks",
        "--stack-status-filter", "CREATE_COMPLETE", "UPDATE_COMPLETE", "DELETE_IN_PROGRESS",
        "--region", region
    ])

def wait_stack_delete(stack_name: str, region: str = "eu-central-1") -> dict:
    """Wait for stack deletion to complete"""
    return run_aws_command([
        "cloudformation", "wait", "stack-delete-complete",
        "--stack-name", stack_name,
        "--region", region
    ])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: aws-cli-mcp.py <command> [args]")
        print("Commands: delete-stack, describe-stack, list-stacks, wait-delete")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "delete-stack":
        stack_name = sys.argv[2] if len(sys.argv) > 2 else "zalt-auth"
        region = sys.argv[3] if len(sys.argv) > 3 else "eu-central-1"
        result = delete_stack(stack_name, region)
        print(json.dumps(result, indent=2))
    
    elif command == "describe-stack":
        stack_name = sys.argv[2] if len(sys.argv) > 2 else "zalt-auth"
        region = sys.argv[3] if len(sys.argv) > 3 else "eu-central-1"
        result = describe_stack(stack_name, region)
        print(json.dumps(result, indent=2))
    
    elif command == "list-stacks":
        region = sys.argv[2] if len(sys.argv) > 2 else "eu-central-1"
        result = list_stacks(region)
        print(json.dumps(result, indent=2))
    
    elif command == "wait-delete":
        stack_name = sys.argv[2] if len(sys.argv) > 2 else "zalt-auth"
        region = sys.argv[3] if len(sys.argv) > 3 else "eu-central-1"
        result = wait_stack_delete(stack_name, region)
        print(json.dumps(result, indent=2))
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
