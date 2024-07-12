#!/usr/bin/env python3

import os
import subprocess
import sys
import aiofiles
import asyncio
import random
import time
from tqdm import tqdm
import argparse
import requests

def create_directory(target):
    if not os.path.exists(target):
        os.makedirs(target)
    os.chdir(target)

def run_command(command, outputfile):
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if stdout:
            with open(outputfile, 'a') as f:
                f.write(stdout.decode())

        if stderr:
            print(f"[Error] {stderr.decode()}")

    except Exception as e:
        print(f"[Exception] Error running command {command}: {e}")

async def merge_files(output_files, merged_file):
    try:
        async with aiofiles.open(merged_file, 'w') as outfile:
            for name in tqdm(output_files, desc="Merging files", unit="file"):
                async with aiofiles.open(name, 'r') as infile:
                    content = await infile.read()
                    await outfile.write(content)
    except Exception as e:
        print(f"[Exception] Error merging files: {e}")

async def filter_urls(input_file, target):
    try:
        async with aiofiles.open(input_file, 'r') as infile:
            unique_urls = set(await infile.readlines())

        sorted_urls = sorted(unique_urls)

        async with aiofiles.open(f"unique_urls.txt", 'w') as outfile:
            await outfile.writelines(sorted_urls)

        parameters = set()
        for url in sorted_urls:
            if '?' in url:
                params = url.split('?')[1].split('&')
                parameters.update(params)

        async with aiofiles.open(f"{target}_parameters.txt", 'w') as param_file:
            await param_file.writelines(f"{param}\n" for param in parameters)

        async with aiofiles.open(f"unique_urls.txt", 'r') as infile:
            async with aiofiles.open(f"{target}_urls_with_params.txt", 'w') as with_params, aiofiles.open(f"{target}_urls_without_params.txt", 'w') as without_params:
                async for line in infile:
                    if '=' in line:
                        await with_params.write(line)
                    else:
                        await without_params.write(line)
    except Exception as e:
        print(f"[Exception] Error filtering URLs: {e}")

async def filter_xss_sqli_files(input_file):
    try:
        async with aiofiles.open(input_file, 'r') as infile:
            async with aiofiles.open("xss_sqli_files.txt", 'w') as outfile:
                async for line in infile:
                    if any(ext in line for ext in [".php", ".asp", ".aspx", ".cfm", ".jsp"]):
                        await outfile.write(line)
    except Exception as e:
        print(f"[Exception] Error filtering XSS/SQLi files: {e}")

async def probe_urls(input_file, output_file):
    try:
        command = f"httpx -l {input_file} -o {output_file} -silent"
        process = await asyncio.create_subprocess_shell(command)
        await process.communicate()
    except Exception as e:
        print(f"[Exception] Error probing URLs: {e}")

async def check_rate_limiting(target):
    try:
        response = requests.get(f"https://{target}")
        if response.status_code == 429:
            print("[Rate Limit] Detected rate limiting (429 Too Many Requests).")
            return True
    except Exception as e:
        print(f"[Exception] Error checking rate limiting: {e}")
    return False

async def handle_rate_limiting(target, max_workers):
    print(f"Rate limiting detected. Please open https://{target} in your browser to manually verify.")
    print("Options:")
    print("1. Stop the scan and ask for a new target.")
    print("2. Check each minute if the timeout has been lifted and automatically continue, but slow down the script to -1 thread each time (minimum of 1).")
    
    choice = input("Enter your choice (1 or 2): ")
    if choice == "1":
        return False, max_workers
    elif choice == "2":
        while True:
            time.sleep(60)
            if not await check_rate_limiting(target):
                print("Rate limit lifted. Resuming scan.")
                return True, max(1, max_workers - 1)  # Ensure minimum of 1 worker
            print("Rate limit still in effect. Checking again in 1 minute...")
    return False, max_workers

def run_commands(commands):
    for i, (tool, cmd) in enumerate(tqdm(commands.items(), desc="Running commands", unit="command")):
        output_file = cmd.split("| tee -a ")[1] if "| tee -a " in cmd else f"{tool}.txt"
        print(f"Running {i+1}/{len(commands)} - {tool}...")
        run_command(cmd.split("| tee -a ")[0], output_file)
        if random.random() < 0.3:  # 30% chance to check for rate limiting
            if asyncio.run(check_rate_limiting(target)):
                continue_scan, max_workers = asyncio.run(handle_rate_limiting(target, max_workers))
                if not continue_scan:
                    print("Stopping scan. Please provide a new target.")
                    return

async def main(target, exclude_tools):
    create_directory(target)

    all_tools = {
        'waybackurls': f"waybackurls {target} | tee -a waybackurls.txt",
        'getallurls': f"getallurls {target} | tee -a getallurls.txt",
        'gau': f"gau {target} | tee -a gau.txt",
        'waymore': f"python waymore.py -i {target} -mode U -oU waymore.txt",
        'katana': f"katana -u {target} -kf 3 | tee -a katana.txt",
        'subdominator': f"subdominator -d {target} -o domains.txt",
        'hakrawler': f"cat domains.txt | hakrawler | tee -a links.txt",
        'subprober': f"subprober -f domains.txt -sc -ar -o 200-codes-urls.txt -nc -mc 200 -c 30"
    }

    estimated_times = {
        'waybackurls': 2,
        'getallurls': 2,
        'gau': 2,
        'waymore': 3,
        'katana': 7,
        'subdominator': 5,
        'hakrawler': 3,
        'subprober': 5
    }

    # Exclude specified tools
    commands = {tool: cmd for tool, cmd in all_tools.items() if tool not in exclude_tools}
    total_estimated_time = sum(estimated_times[tool] for tool in commands)

    max_workers = 5
    run_commands(commands)

    await merge_files([f"{tool}.txt" for tool in all_tools if tool not in exclude_tools], "output.txt")

    await filter_urls("output.txt", target)

    await filter_xss_sqli_files("unique_urls.txt")

    print("Probing URLs with httpx...")
    await probe_urls("unique_urls.txt", "live_urls.txt")

    # Prompt user to test with SQLMap
    choice = input("Do you want to test the URLs in xss_sqli_files.txt for SQLi with SQLMap? (yes/no): ")
    if choice.lower() == 'yes':
        sqlmap_command = f"sqlmap -m xss_sqli_files.txt --batch --risk 2 --level 2"
        print(f"Running SQLMap with command: {sqlmap_command}")
        subprocess.run(sqlmap_command, shell=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='URL and parameter enumeration script for testing the target website. Tools used: waybackurls, getallurls, gau, waymore, katana, subdominator, hakrawler, subprober.')
    parser.add_argument('target', help='The target website to enumerate.')
    parser.add_argument('--exclude', nargs='+', choices=['waybackurls', 'getallurls', 'gau', 'waymore', 'katana', 'subdominator', 'hakrawler', 'subprober'], help='Tools to exclude from the enumeration.')
    args = parser.parse_args()

    target = args.target
    exclude_tools = args.exclude if args.exclude else []

    asyncio.run(main(target, exclude_tools))
